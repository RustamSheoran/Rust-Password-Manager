use std::{
    io::{self, Stdout},
    time::{Duration, Instant},
};

use arboard::Clipboard;
use chrono::{DateTime, Local, LocalResult, TimeZone};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use fuzzy_matcher::{FuzzyMatcher, skim::SkimMatcherV2};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    prelude::{Alignment, Color, Frame, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use secrecy::{ExposeSecret, SecretString};

use crate::{
    cli::commands::{generate_password, unix_timestamp},
    error::Result,
    security::memory::{
        empty_secret, pop_secret_char, push_secret_char, secret_from_string, secret_len,
        take_secret,
    },
    vault::{Vault, VaultStore},
};

type AppTerminal = Terminal<CrosstermBackend<Stdout>>;

#[derive(Debug, Clone, Copy)]
pub struct TuiConfig {
    pub auto_lock_timeout: Duration,
    pub reveal_timeout: Duration,
    pub clipboard_timeout: Duration,
    pub ctrl_c_grace_period: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiOutcome {
    Quit,
    Locked,
}

pub fn run(
    store: &VaultStore,
    vault: Vault,
    master: SecretString,
    config: TuiConfig,
) -> Result<TuiOutcome> {
    let mut terminal = init_terminal()?;
    let mut app = App::new(vault, master, config);
    let result = app.event_loop(store, &mut terminal);
    app.clear_sensitive_state();
    let restore_result = restore_terminal(&mut terminal);

    match (result, restore_result) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn init_terminal() -> Result<AppTerminal> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut AppTerminal) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

struct App {
    vault: Vault,
    master: SecretString,
    config: TuiConfig,
    matcher: SkimMatcherV2,
    filtered_sites: Vec<String>,
    selected: usize,
    search_mode: bool,
    search_query: String,
    sort_order: SortOrder,
    help_visible: bool,
    add_form: Option<AddForm>,
    status: String,
    revealed_site: Option<String>,
    revealed_until: Option<Instant>,
    clipboard_deadline: Option<Instant>,
    clipboard: Option<Clipboard>,
    last_activity: Instant,
    last_quit_attempt: Option<Instant>,
    quit_confirmation_visible: bool,
    pending_delete_site: Option<String>,
    dirty: bool,
}

impl App {
    fn new(vault: Vault, master: SecretString, config: TuiConfig) -> Self {
        let clipboard = Clipboard::new().ok();
        let mut app = Self {
            vault,
            master,
            config,
            matcher: SkimMatcherV2::default(),
            filtered_sites: Vec::new(),
            selected: 0,
            search_mode: false,
            search_query: String::new(),
            sort_order: SortOrder::Site,
            help_visible: false,
            add_form: None,
            status: "Vault unlocked. Press ? for keybindings.".into(),
            revealed_site: None,
            revealed_until: None,
            clipboard_deadline: None,
            clipboard,
            last_activity: Instant::now(),
            last_quit_attempt: None,
            quit_confirmation_visible: false,
            pending_delete_site: None,
            dirty: false,
        };
        app.refresh_entries();
        app.status = app.hidden_password_status();
        app
    }

    fn event_loop(&mut self, store: &VaultStore, terminal: &mut AppTerminal) -> Result<TuiOutcome> {
        loop {
            self.expire_timers();
            if self.last_activity.elapsed() >= self.config.auto_lock_timeout {
                self.persist_if_dirty(store)?;
                self.status = "Vault auto-locked because of inactivity".into();
                return Ok(TuiOutcome::Locked);
            }

            terminal.draw(|frame| draw(frame, self))?;

            if !event::poll(Duration::from_millis(200))? {
                continue;
            }

            let Event::Key(key) = event::read()? else {
                continue;
            };

            if key.kind != KeyEventKind::Press {
                continue;
            }

            self.last_activity = Instant::now();

            if let Some(outcome) = self.handle_key(store, key)? {
                return Ok(outcome);
            }
        }
    }

    fn handle_key(&mut self, store: &VaultStore, key: KeyEvent) -> Result<Option<TuiOutcome>> {
        if is_ctrl_c(key) {
            return self.handle_ctrl_c(store);
        }

        if self.quit_confirmation_visible {
            self.handle_quit_confirmation_key(key);
            return Ok(None);
        }

        if self.pending_delete_site.is_some() {
            self.handle_delete_confirmation_key(store, key)?;
            return Ok(None);
        }

        if self.help_visible {
            self.handle_help_key(key);
            return Ok(None);
        }

        if self.add_form.is_some() {
            self.handle_add_form_key(store, key)?;
            return Ok(None);
        }

        if self.search_mode {
            self.handle_search_key(key);
            return Ok(None);
        }

        match key.code {
            KeyCode::Char('q') => self.status = "Use Ctrl+C to exit".into(),
            KeyCode::Char('?') | KeyCode::F(1) => self.toggle_help(),
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('/') => {
                self.hide_revealed_password();
                self.search_mode = true;
                self.status = "Search mode: type to filter, Esc to exit".into();
            }
            KeyCode::Enter => self.reveal_selected()?,
            KeyCode::Char('y') => self.copy_selected()?,
            KeyCode::Char('a') => self.start_add(),
            KeyCode::Char('d') => self.delete_selected(store)?,
            KeyCode::Char('s') => self.toggle_sort(),
            _ => {}
        }

        Ok(None)
    }

    fn handle_ctrl_c(&mut self, store: &VaultStore) -> Result<Option<TuiOutcome>> {
        let now = Instant::now();
        if self
            .last_quit_attempt
            .is_some_and(|last| now.duration_since(last) <= self.config.ctrl_c_grace_period)
        {
            self.persist_if_dirty(store)?;
            return Ok(Some(TuiOutcome::Quit));
        }

        self.hide_revealed_password();
        self.pending_delete_site = None;
        self.last_quit_attempt = Some(now);
        self.quit_confirmation_visible = true;
        Ok(None)
    }

    fn handle_quit_confirmation_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.cancel_quit_confirmation(),
            KeyCode::Char('c') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.cancel_quit_confirmation()
            }
            _ => {}
        }
    }

    fn cancel_quit_confirmation(&mut self) {
        self.quit_confirmation_visible = false;
        self.last_quit_attempt = None;
        self.status = "Exit cancelled".into();
    }

    fn handle_help_key(&mut self, key: KeyEvent) {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('?') | KeyCode::F(1)) {
            self.help_visible = false;
            self.status = "Closed keyboard help".into();
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.search_mode = false;
                self.status = if self.search_query.is_empty() {
                    "Search cleared".into()
                } else {
                    format!("Filtered by \"{}\"", self.search_query)
                };
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.refresh_entries();
            }
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.search_query.push(ch);
                self.refresh_entries();
            }
            KeyCode::Down => self.move_selection(1),
            KeyCode::Up => self.move_selection(-1),
            _ => {}
        }
    }

    fn handle_add_form_key(&mut self, store: &VaultStore, key: KeyEvent) -> Result<()> {
        let Some(form) = self.add_form.as_mut() else {
            return Ok(());
        };

        match key.code {
            KeyCode::Esc => {
                self.add_form = None;
                self.status = "Add entry cancelled".into();
            }
            KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                form.password = secret_from_string(generate_password(24, true)?);
                self.status = "Generated a 24-character password for the new entry".into();
            }
            KeyCode::Tab | KeyCode::Down => form.next_field(),
            KeyCode::BackTab | KeyCode::Up => form.previous_field(),
            KeyCode::Enter => {
                if form.active_field == AddField::Password {
                    self.submit_add_form(store)?;
                } else {
                    form.next_field();
                }
            }
            KeyCode::Backspace => form.backspace(),
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => form.push(ch),
            _ => {}
        }

        Ok(())
    }

    fn submit_add_form(&mut self, store: &VaultStore) -> Result<()> {
        let Some(mut form) = self.add_form.take() else {
            return Ok(());
        };

        let site = form.site.trim().to_owned();
        if site.is_empty() {
            self.status = "Site cannot be empty".into();
            self.add_form = Some(form);
            return Ok(());
        }

        let username = std::mem::take(&mut form.username);
        let password = take_secret(&mut form.password);
        let now = unix_timestamp()?;

        match self.vault.add(site.clone(), username, password, false, now) {
            Ok(()) => {
                self.persist(store)?;
                self.refresh_entries();
                self.select_site(&site);
                self.status = format!("Added {site}");
            }
            Err(error) => {
                self.status = error.to_string();
                self.add_form = Some(form);
            }
        }

        Ok(())
    }

    fn reveal_selected(&mut self) -> Result<()> {
        let Some(site) = self.selected_site().map(ToOwned::to_owned) else {
            self.status = "No entry selected".into();
            return Ok(());
        };

        if self.is_password_revealed(&site) {
            self.hide_revealed_password();
            self.status = self.hidden_password_status();
            return Ok(());
        }

        self.vault.touch(&site, unix_timestamp()?)?;
        self.dirty = true;
        self.revealed_site = Some(site.clone());
        self.revealed_until = Some(Instant::now() + self.config.reveal_timeout);
        self.status = format!("Password for {site} revealed");
        self.refresh_entries();
        Ok(())
    }

    fn copy_selected(&mut self) -> Result<()> {
        let Some(site) = self.selected_site().map(ToOwned::to_owned) else {
            self.status = "No entry selected".into();
            return Ok(());
        };

        let password = self.vault.get(&site)?.password.expose_secret().to_owned();
        if self.clipboard.is_none() {
            self.clipboard = Clipboard::new().ok();
        }

        let Some(clipboard) = self.clipboard.as_mut() else {
            self.status = "Clipboard is unavailable in this environment".into();
            return Ok(());
        };

        if clipboard.set_text(password).is_err() {
            self.status = "Failed to update clipboard".into();
            return Ok(());
        }

        self.vault.touch(&site, unix_timestamp()?)?;
        self.dirty = true;
        self.clipboard_deadline = Some(Instant::now() + self.config.clipboard_timeout);
        self.status = format!(
            "Copied password for {site}; clipboard will clear in {} seconds",
            self.config.clipboard_timeout.as_secs()
        );
        self.refresh_entries();
        Ok(())
    }

    fn delete_selected(&mut self, _store: &VaultStore) -> Result<()> {
        let Some(site) = self.selected_site().map(ToOwned::to_owned) else {
            self.status = "No entry selected".into();
            return Ok(());
        };

        self.hide_revealed_password();
        self.pending_delete_site = Some(site.clone());
        self.status = format!("Delete {site}? Press d to confirm, c or Esc to cancel");
        Ok(())
    }

    fn handle_delete_confirmation_key(&mut self, store: &VaultStore, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('d') | KeyCode::Enter => self.confirm_delete(store)?,
            KeyCode::Esc => self.cancel_delete_confirmation(),
            KeyCode::Char('c') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.cancel_delete_confirmation()
            }
            _ => {}
        }
        Ok(())
    }

    fn confirm_delete(&mut self, store: &VaultStore) -> Result<()> {
        let Some(site) = self.pending_delete_site.take() else {
            return Ok(());
        };

        self.vault.delete(&site)?;
        self.persist(store)?;
        self.refresh_entries();
        self.status = format!("Deleted {site}");
        Ok(())
    }

    fn cancel_delete_confirmation(&mut self) {
        self.pending_delete_site = None;
        self.status = "Delete cancelled".into();
    }

    fn start_add(&mut self) {
        self.hide_revealed_password();
        self.add_form = Some(AddForm::default());
        self.status =
            "Add mode: Tab switches fields, Ctrl+G generates, Enter saves, Esc cancels".into();
    }

    fn toggle_sort(&mut self) {
        self.sort_order = match self.sort_order {
            SortOrder::Site => SortOrder::LastAccessed,
            SortOrder::LastAccessed => SortOrder::Site,
        };
        self.refresh_entries();
        self.status = match self.sort_order {
            SortOrder::Site => "Sorted alphabetically".into(),
            SortOrder::LastAccessed => "Sorted by last accessed".into(),
        };
    }

    fn move_selection(&mut self, delta: isize) {
        let previous_selected = self.selected_site().map(ToOwned::to_owned);
        self.pending_delete_site = None;
        if self.filtered_sites.is_empty() {
            self.selected = 0;
            self.handle_selection_change(previous_selected);
            return;
        }

        let len = self.filtered_sites.len() as isize;
        let selected = (self.selected as isize + delta).rem_euclid(len) as usize;
        self.selected = selected;
        self.handle_selection_change(previous_selected);
    }

    fn selected_site(&self) -> Option<&str> {
        self.filtered_sites.get(self.selected).map(String::as_str)
    }

    fn select_site(&mut self, site: &str) {
        let previous_selected = self.selected_site().map(ToOwned::to_owned);
        if let Some(index) = self.filtered_sites.iter().position(|item| item == site) {
            self.selected = index;
        }
        self.handle_selection_change(previous_selected);
    }

    fn refresh_entries(&mut self) {
        let previous_selected = self.selected_site().map(ToOwned::to_owned);
        let query = self.search_query.trim();
        let mut entries = self
            .vault
            .iter()
            .filter_map(|(site, entry)| {
                if query.is_empty() {
                    return Some((
                        site.clone(),
                        None,
                        entry.last_accessed_at.unwrap_or_default(),
                    ));
                }

                let site_score = self.matcher.fuzzy_match(site, query);
                let username_score = self.matcher.fuzzy_match(&entry.username, query);
                let (match_priority, score) = match (site_score, username_score) {
                    (Some(score), _) => (2_i32, score),
                    (None, Some(score)) => (1_i32, score),
                    (None, None) => return None,
                };
                Some((
                    site.clone(),
                    Some((match_priority, score)),
                    entry.last_accessed_at.unwrap_or_default(),
                ))
            })
            .collect::<Vec<_>>();

        if query.is_empty() {
            match self.sort_order {
                SortOrder::Site => entries.sort_by(|left, right| left.0.cmp(&right.0)),
                SortOrder::LastAccessed => entries
                    .sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0))),
            }
        } else {
            entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        }

        self.filtered_sites = entries.into_iter().map(|entry| entry.0).collect();
        if self.filtered_sites.is_empty() {
            self.selected = 0;
        } else if let Some(previous_site) = previous_selected.as_deref() {
            if let Some(index) = self
                .filtered_sites
                .iter()
                .position(|site| site == previous_site)
            {
                self.selected = index;
            } else if self.selected >= self.filtered_sites.len() {
                self.selected = self.filtered_sites.len() - 1;
            }
        } else if self.selected >= self.filtered_sites.len() {
            self.selected = self.filtered_sites.len() - 1;
        }

        self.handle_selection_change(previous_selected);
    }

    fn expire_timers(&mut self) {
        let now = Instant::now();

        if self.quit_deadline().is_some_and(|deadline| now >= deadline) {
            self.quit_confirmation_visible = false;
            self.last_quit_attempt = None;
            self.status = self.hidden_password_status();
        }

        if self.revealed_until.is_some_and(|deadline| now >= deadline) {
            self.hide_revealed_password();
            self.status = self.hidden_password_status();
        }

        if self
            .clipboard_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            self.clear_clipboard();
            self.status = self.hidden_password_status();
        }
    }

    fn clear_sensitive_state(&mut self) {
        self.hide_revealed_password();
        self.add_form = None;
        self.clear_clipboard();
    }

    fn clear_clipboard(&mut self) {
        if let Some(clipboard) = self.clipboard.as_mut() {
            let _ = clipboard.set_text(String::new());
        }
        self.clipboard_deadline = None;
    }

    fn persist(&mut self, store: &VaultStore) -> Result<()> {
        store.save(&self.master, &self.vault)?;
        self.dirty = false;
        Ok(())
    }

    fn persist_if_dirty(&mut self, store: &VaultStore) -> Result<()> {
        if self.dirty {
            self.persist(store)?;
        }
        Ok(())
    }

    fn toggle_help(&mut self) {
        self.help_visible = !self.help_visible;
        if self.help_visible {
            self.hide_revealed_password();
        }
        self.status = if self.help_visible {
            "Keyboard help open. Press ? or Esc to close.".into()
        } else {
            "Closed keyboard help".into()
        };
    }

    fn details_lines(&self) -> Vec<Line<'static>> {
        let Some(site) = self.selected_site() else {
            return vec![
                Line::from("Vault is empty"),
                Line::from(""),
                Line::from("Press a to add your first entry."),
            ];
        };

        let entry = match self.vault.get(site) {
            Ok(entry) => entry,
            Err(_) => {
                return vec![Line::from("Selected entry could not be loaded")];
            }
        };

        let password = if self.is_password_revealed(site) {
            entry.password.expose_secret().to_owned()
        } else {
            "•".repeat(secret_len(&entry.password).max(8))
        };

        vec![
            Line::from(vec![
                Span::styled("Site: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(site.to_owned()),
            ]),
            Line::from(vec![
                Span::styled("Username: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(entry.username.clone()),
            ]),
            Line::from(vec![
                Span::styled("Password: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(password),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Created: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format_timestamp(entry.created_at)),
            ]),
            Line::from(vec![
                Span::styled("Updated: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format_timestamp(entry.updated_at)),
            ]),
            Line::from(vec![
                Span::styled(
                    "Last accessed: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(
                    entry
                        .last_accessed_at
                        .map(format_timestamp)
                        .unwrap_or_else(|| "never".into()),
                ),
            ]),
        ]
    }

    fn is_password_revealed(&self, site: &str) -> bool {
        self.revealed_site.as_deref() == Some(site)
            && self
                .revealed_until
                .is_some_and(|deadline| Instant::now() < deadline)
    }

    fn footer_lines(&self) -> Vec<Line<'static>> {
        let primary = self.dynamic_status_line();
        vec![
            Line::from(primary),
            Line::from(
                "j/k move  / search  enter reveal/hide  y copy  a add  d delete  s sort  ? help  Ctrl+C exit",
            ),
        ]
    }

    fn help_lines(&self) -> Vec<Line<'static>> {
        vec![
            Line::from(vec![Span::styled(
                "Navigation",
                Style::default().add_modifier(Modifier::BOLD),
            )]),
            Line::from("j / Down        Move to the next entry"),
            Line::from("k / Up          Move to the previous entry"),
            Line::from("/               Start fuzzy search"),
            Line::from("s               Toggle sorting by site / last accessed"),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Entry Actions",
                Style::default().add_modifier(Modifier::BOLD),
            )]),
            Line::from("Enter           Toggle password reveal on or off"),
            Line::from("y               Copy password to clipboard"),
            Line::from("a               Open the add-entry dialog"),
            Line::from("d               Open the delete confirmation screen"),
            Line::from("Ctrl+G          Generate a password in the add dialog"),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Safety",
                Style::default().add_modifier(Modifier::BOLD),
            )]),
            Line::from("Ctrl+C          Show a 3-second exit confirmation"),
            Line::from("d / Enter       Confirm entry deletion"),
            Line::from("c / Esc         Cancel search or close a confirmation screen"),
            Line::from("q               Disabled for exit; use Ctrl+C instead"),
            Line::from("Esc             Leave search or close dialogs/help"),
            Line::from(""),
            Line::from("Press ? or F1 to toggle this help."),
        ]
    }

    fn dynamic_status_line(&self) -> String {
        if self.quit_confirmation_visible
            && let Some(remaining) = self.quit_countdown_seconds()
        {
            return format!(
                "Press Ctrl+C again to quit in {remaining}s. Press c or Esc to cancel."
            );
        }

        if let Some(site) = self.selected_site()
            && self.is_password_revealed(site)
            && let Some(remaining) = self.reveal_countdown_seconds()
        {
            return format!("Password for {site} revealed for {remaining}s");
        }

        self.status.clone()
    }

    fn handle_selection_change(&mut self, previous_selected: Option<String>) {
        let current_selected = self.selected_site().map(ToOwned::to_owned);
        if previous_selected == current_selected {
            return;
        }

        if self.revealed_site.as_deref() != current_selected.as_deref() {
            self.hide_revealed_password();
        }

        self.status = self.hidden_password_status();
    }

    fn hidden_password_status(&self) -> String {
        self.selected_site()
            .map(|site| format!("Password for {site} is hidden"))
            .unwrap_or_else(|| "Vault unlocked. Press ? for keybindings.".into())
    }

    fn hide_revealed_password(&mut self) {
        self.revealed_site = None;
        self.revealed_until = None;
    }

    fn quit_deadline(&self) -> Option<Instant> {
        self.last_quit_attempt
            .map(|started_at| started_at + self.config.ctrl_c_grace_period)
    }

    fn quit_countdown_seconds(&self) -> Option<u64> {
        self.quit_deadline().and_then(countdown_seconds_until)
    }

    fn reveal_countdown_seconds(&self) -> Option<u64> {
        self.revealed_until.and_then(countdown_seconds_until)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortOrder {
    Site,
    LastAccessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddField {
    Site,
    Username,
    Password,
}

struct AddForm {
    site: String,
    username: String,
    password: SecretString,
    active_field: AddField,
}

impl Default for AddForm {
    fn default() -> Self {
        Self {
            site: String::new(),
            username: String::new(),
            password: empty_secret(),
            active_field: AddField::Site,
        }
    }
}

impl AddForm {
    fn next_field(&mut self) {
        self.active_field = match self.active_field {
            AddField::Site => AddField::Username,
            AddField::Username => AddField::Password,
            AddField::Password => AddField::Site,
        };
    }

    fn previous_field(&mut self) {
        self.active_field = match self.active_field {
            AddField::Site => AddField::Password,
            AddField::Username => AddField::Site,
            AddField::Password => AddField::Username,
        };
    }

    fn push(&mut self, ch: char) {
        match self.active_field {
            AddField::Site => self.site.push(ch),
            AddField::Username => self.username.push(ch),
            AddField::Password => push_secret_char(&mut self.password, ch),
        }
    }

    fn backspace(&mut self) {
        match self.active_field {
            AddField::Site => {
                self.site.pop();
            }
            AddField::Username => {
                self.username.pop();
            }
            AddField::Password => pop_secret_char(&mut self.password),
        }
    }
}

fn draw(frame: &mut Frame<'_>, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2)])
        .split(frame.area());

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(layout[0]);

    let list_items = if app.filtered_sites.is_empty() {
        vec![ListItem::new("No entries")]
    } else {
        app.filtered_sites
            .iter()
            .map(|site| ListItem::new(site.as_str()))
            .collect::<Vec<_>>()
    };

    let list_title = if app.search_query.is_empty() {
        format!("Entries [{}]", app.sort_order_label())
    } else {
        format!("Entries [{}] /{}", app.sort_order_label(), app.search_query)
    };
    let list = List::new(list_items)
        .block(Block::default().borders(Borders::ALL).title(list_title))
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .highlight_symbol(">> ");
    let mut list_state = ListState::default();
    if !app.filtered_sites.is_empty() {
        list_state.select(Some(app.selected));
    }
    frame.render_stateful_widget(list, panes[0], &mut list_state);

    let details = Paragraph::new(app.details_lines())
        .block(Block::default().borders(Borders::ALL).title("Details"))
        .wrap(Wrap { trim: false });
    frame.render_widget(details, panes[1]);

    let status = Paragraph::new(app.footer_lines())
        .alignment(Alignment::Left)
        .style(Style::default().fg(Color::Black).bg(Color::Cyan));
    frame.render_widget(status, layout[1]);

    if app.help_visible {
        render_help_modal(frame, app);
    }

    if let Some(form) = &app.add_form {
        render_add_modal(frame, form);
    }

    if let Some(site) = app.pending_delete_site.as_deref() {
        render_delete_confirmation(frame, site);
    }

    if app.quit_confirmation_visible {
        render_quit_confirmation(frame, app.quit_countdown_seconds().unwrap_or_default());
    }
}

fn render_help_modal(frame: &mut Frame<'_>, app: &App) {
    let area = centered_rect(72, 68, frame.area());
    frame.render_widget(Clear, area);

    let help = Paragraph::new(app.help_lines())
        .block(
            Block::default()
                .title("Keyboard Help")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(help, area);
}

fn render_add_modal(frame: &mut Frame<'_>, form: &AddForm) {
    let area = centered_rect(60, 45, frame.area());
    frame.render_widget(Clear, area);

    let block = Block::default().title("Add Entry").borders(Borders::ALL);
    frame.render_widget(block, area);

    let inner = Layout::default()
        .margin(1)
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);

    frame.render_widget(
        field_paragraph("Site", &form.site, form.active_field == AddField::Site),
        inner[0],
    );
    frame.render_widget(
        field_paragraph(
            "Username",
            &form.username,
            form.active_field == AddField::Username,
        ),
        inner[1],
    );
    frame.render_widget(
        field_paragraph(
            "Password",
            &"•".repeat(secret_len(&form.password).max(1)),
            form.active_field == AddField::Password,
        ),
        inner[2],
    );
    frame.render_widget(
        Paragraph::new("Tab switches fields, Ctrl+G generates, Enter saves, Esc cancels")
            .style(Style::default().fg(Color::Gray)),
        inner[3],
    );
}

fn render_quit_confirmation(frame: &mut Frame<'_>, remaining_seconds: u64) {
    let area = frame.area();
    frame.render_widget(Clear, area);

    let overlay = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "Confirm Exit",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!(
            "Press Ctrl+C again within {remaining_seconds}s to quit."
        )),
        Line::from(""),
        Line::from("Press c or Esc to stay in the vault."),
    ])
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::White).bg(Color::Black)),
    );

    frame.render_widget(overlay, area);
}

fn render_delete_confirmation(frame: &mut Frame<'_>, site: &str) {
    let area = frame.area();
    frame.render_widget(Clear, area);

    let overlay = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "Confirm Delete",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("Delete the entry for {site}?")),
        Line::from(""),
        Line::from("Press d or Enter to delete it permanently."),
        Line::from(""),
        Line::from("Press c or Esc to stay in the vault."),
    ])
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::White).bg(Color::Black)),
    );

    frame.render_widget(overlay, area);
}

fn field_paragraph<'a>(label: &'a str, value: &'a str, focused: bool) -> Paragraph<'a> {
    let style = if focused {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    Paragraph::new(Line::from(vec![
        Span::styled(format!("{label}: "), style),
        Span::raw(value),
    ]))
}

fn centered_rect(horizontal: u16, vertical: u16, area: Rect) -> Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - vertical) / 2),
            Constraint::Percentage(vertical),
            Constraint::Percentage((100 - vertical) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - horizontal) / 2),
            Constraint::Percentage(horizontal),
            Constraint::Percentage((100 - horizontal) / 2),
        ])
        .split(popup[1])[1]
}

fn is_ctrl_c(key: KeyEvent) -> bool {
    key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)
}

fn format_timestamp(timestamp: u64) -> String {
    if timestamp == 0 {
        return "legacy".into();
    }

    let Some(timestamp) = i64::try_from(timestamp).ok() else {
        return "invalid time".into();
    };

    match Local.timestamp_opt(timestamp, 0) {
        LocalResult::Single(datetime) => format_datetime(datetime),
        _ => "invalid time".into(),
    }
}

fn countdown_seconds_until(deadline: Instant) -> Option<u64> {
    let now = Instant::now();
    if now >= deadline {
        return None;
    }

    let remaining = deadline.duration_since(now);
    Some(remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0))
}

impl App {
    fn sort_order_label(&self) -> &'static str {
        match self.sort_order {
            SortOrder::Site => "site",
            SortOrder::LastAccessed => "last-accessed",
        }
    }
}

fn format_datetime<Tz>(datetime: DateTime<Tz>) -> String
where
    Tz: TimeZone,
    Tz::Offset: std::fmt::Display,
{
    datetime
        .format("%H:%M:%S %-d %b %Y")
        .to_string()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use chrono::{FixedOffset, TimeZone};
    use secrecy::SecretString;
    use tempfile::tempdir;

    use super::{App, TuiConfig, format_datetime};
    use crate::vault::{Vault, VaultStore};

    fn test_config() -> TuiConfig {
        TuiConfig {
            auto_lock_timeout: std::time::Duration::from_secs(300),
            reveal_timeout: std::time::Duration::from_secs(8),
            clipboard_timeout: std::time::Duration::from_secs(15),
            ctrl_c_grace_period: std::time::Duration::from_secs(3),
        }
    }

    #[test]
    fn pressing_enter_twice_hides_the_revealed_password() {
        let directory = tempdir().expect("tempdir");
        let store = VaultStore::new(directory.path().join("vault.json"));
        let master = SecretString::new("correct horse battery staple".into());
        let mut vault = Vault::default();
        vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("hunter2".into()),
                false,
                100,
            )
            .expect("add entry");
        store.save(&master, &vault).expect("save vault");

        let mut app = App::new(vault, master, test_config());

        app.reveal_selected().expect("first reveal");
        assert!(app.is_password_revealed("example.com"));
        assert!(app.dirty);

        app.reveal_selected().expect("second reveal toggles off");
        assert!(!app.is_password_revealed("example.com"));
        assert_eq!(app.status, "Password for example.com is hidden");

        app.persist_if_dirty(&store).expect("persist dirty state");
        assert!(!app.dirty);
    }

    #[test]
    fn ctrl_c_requires_a_second_press_within_the_grace_period() {
        let directory = tempdir().expect("tempdir");
        let store = VaultStore::new(directory.path().join("vault.json"));
        let app_master = SecretString::new("correct horse battery staple".into());
        let app_vault = Vault::default();
        let mut app = App::new(app_vault, app_master, test_config());

        let first = app.handle_ctrl_c(&store).expect("first ctrl+c");
        assert!(first.is_none());
        assert!(app.quit_confirmation_visible);

        let second = app.handle_ctrl_c(&store).expect("second ctrl+c");
        assert_eq!(second, Some(super::TuiOutcome::Quit));
    }

    #[test]
    fn exit_confirmation_times_out_and_returns_to_the_vault() {
        let app_master = SecretString::new("correct horse battery staple".into());
        let mut vault = Vault::default();
        vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("hunter2".into()),
                false,
                100,
            )
            .expect("add entry");
        let mut app = App::new(vault, app_master, test_config());
        app.quit_confirmation_visible = true;
        app.last_quit_attempt = Some(std::time::Instant::now() - std::time::Duration::from_secs(4));

        app.expire_timers();

        assert!(!app.quit_confirmation_visible);
        assert_eq!(app.status, "Password for example.com is hidden");
    }

    #[test]
    fn formats_timestamps_in_requested_shape() {
        let offset = FixedOffset::east_opt(5 * 3600 + 30 * 60).expect("valid offset");
        let datetime = offset
            .with_ymd_and_hms(2026, 1, 24, 13, 15, 6)
            .single()
            .expect("valid datetime");

        assert_eq!(format_datetime(datetime), "13:15:06 24 jan 2026");
    }

    #[test]
    fn q_no_longer_exits_the_app() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let directory = tempdir().expect("tempdir");
        let store = VaultStore::new(directory.path().join("vault.json"));
        let app_master = SecretString::new("correct horse battery staple".into());
        let app_vault = Vault::default();
        let mut app = App::new(app_vault, app_master, test_config());

        let outcome = app
            .handle_key(
                &store,
                KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            )
            .expect("handle q");

        assert!(outcome.is_none());
        assert_eq!(app.status, "Use Ctrl+C to exit");
        assert!(!app.quit_confirmation_visible);
    }

    #[test]
    fn c_cancels_the_exit_confirmation_overlay() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let directory = tempdir().expect("tempdir");
        let store = VaultStore::new(directory.path().join("vault.json"));
        let app_master = SecretString::new("correct horse battery staple".into());
        let app_vault = Vault::default();
        let mut app = App::new(app_vault, app_master, test_config());

        app.handle_ctrl_c(&store).expect("first ctrl+c");
        assert!(app.quit_confirmation_visible);

        app.handle_quit_confirmation_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));

        assert!(!app.quit_confirmation_visible);
        assert_eq!(app.status, "Exit cancelled");
    }

    #[test]
    fn changing_selection_hides_the_previous_password() {
        let app_master = SecretString::new("correct horse battery staple".into());
        let mut vault = Vault::default();
        vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("hunter2".into()),
                false,
                100,
            )
            .expect("add first entry");
        vault
            .add(
                "rust-lang.org".into(),
                "ferris".into(),
                SecretString::new("crabtime".into()),
                false,
                101,
            )
            .expect("add second entry");

        let mut app = App::new(vault, app_master, test_config());
        let first_site = app.selected_site().expect("selected site").to_owned();

        app.reveal_selected().expect("reveal selected entry");
        assert!(app.is_password_revealed(&first_site));

        app.move_selection(1);

        let current_site = app.selected_site().expect("new selected site");
        assert_ne!(current_site, first_site);
        assert!(app.revealed_site.is_none());
        assert_eq!(app.status, format!("Password for {current_site} is hidden"));
    }

    #[test]
    fn delete_confirmation_can_be_cancelled_without_removing_the_entry() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let directory = tempdir().expect("tempdir");
        let store = VaultStore::new(directory.path().join("vault.json"));
        let master = SecretString::new("correct horse battery staple".into());
        let mut vault = Vault::default();
        vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("hunter2".into()),
                false,
                100,
            )
            .expect("add entry");

        let mut app = App::new(vault, master, test_config());

        app.handle_key(
            &store,
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        )
        .expect("open delete confirmation");
        assert_eq!(app.pending_delete_site.as_deref(), Some("example.com"));

        app.handle_key(&store, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("cancel delete confirmation");

        assert!(app.pending_delete_site.is_none());
        assert!(app.vault.get("example.com").is_ok());
        assert_eq!(app.status, "Delete cancelled");
    }

    #[test]
    fn delete_confirmation_removes_the_entry_after_confirmation() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let directory = tempdir().expect("tempdir");
        let store = VaultStore::new(directory.path().join("vault.json"));
        let master = SecretString::new("correct horse battery staple".into());
        let mut vault = Vault::default();
        vault
            .add(
                "example.com".into(),
                "alice".into(),
                SecretString::new("hunter2".into()),
                false,
                100,
            )
            .expect("add entry");

        let mut app = App::new(vault, master, test_config());

        app.handle_key(
            &store,
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        )
        .expect("open delete confirmation");
        app.handle_key(
            &store,
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        )
        .expect("confirm delete");

        assert!(app.pending_delete_site.is_none());
        assert!(app.vault.get("example.com").is_err());
        assert_eq!(app.status, "Deleted example.com");
    }

    #[test]
    fn search_mode_only_exits_on_escape() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

        let directory = tempdir().expect("tempdir");
        let store = VaultStore::new(directory.path().join("vault.json"));
        let master = SecretString::new("correct horse battery staple".into());
        let app_vault = Vault::default();
        let mut app = App::new(app_vault, master, test_config());

        app.handle_key(
            &store,
            KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
        )
        .expect("enter search mode");
        assert!(app.search_mode);

        app.handle_key(&store, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("press enter in search mode");
        assert!(app.search_mode);

        app.handle_key(&store, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("exit search mode");
        assert!(!app.search_mode);
    }

    #[test]
    fn fuzzy_search_prioritizes_site_matches_over_username_matches() {
        let master = SecretString::new("correct horse battery staple".into());
        let mut vault = Vault::default();
        vault
            .add(
                "github.com".into(),
                "alice".into(),
                SecretString::new("hunter2".into()),
                false,
                100,
            )
            .expect("add site match");
        vault
            .add(
                "internal.example".into(),
                "github-admin".into(),
                SecretString::new("crabtime".into()),
                false,
                101,
            )
            .expect("add username match");

        let mut app = App::new(vault, master, test_config());
        app.search_query = "github".into();
        app.refresh_entries();

        assert_eq!(
            app.filtered_sites,
            vec!["github.com".to_owned(), "internal.example".to_owned()]
        );
    }
}
