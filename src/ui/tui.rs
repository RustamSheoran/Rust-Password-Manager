use std::{
    io::{self, Stdout},
    time::{Duration, Instant},
};

use arboard::Clipboard;
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
    cli::commands::unix_timestamp,
    error::Result,
    security::memory::{empty_secret, pop_secret_char, push_secret_char, secret_len, take_secret},
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
    add_form: Option<AddForm>,
    status: String,
    revealed_site: Option<String>,
    revealed_until: Option<Instant>,
    clipboard_deadline: Option<Instant>,
    clipboard: Option<Clipboard>,
    last_activity: Instant,
    last_ctrl_c: Option<Instant>,
    pending_delete_site: Option<String>,
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
            add_form: None,
            status: "j/k move  / search  enter reveal  y copy  a add  d delete  s sort  q quit"
                .into(),
            revealed_site: None,
            revealed_until: None,
            clipboard_deadline: None,
            clipboard,
            last_activity: Instant::now(),
            last_ctrl_c: None,
            pending_delete_site: None,
        };
        app.refresh_entries();
        app
    }

    fn event_loop(&mut self, store: &VaultStore, terminal: &mut AppTerminal) -> Result<TuiOutcome> {
        loop {
            self.expire_timers();
            if self.last_activity.elapsed() >= self.config.auto_lock_timeout {
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
            self.reset_ctrl_c_grace_if_needed();

            if let Some(outcome) = self.handle_key(store, key)? {
                return Ok(outcome);
            }
        }
    }

    fn handle_key(&mut self, store: &VaultStore, key: KeyEvent) -> Result<Option<TuiOutcome>> {
        if is_ctrl_c(key) {
            return Ok(self.handle_ctrl_c());
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
            KeyCode::Char('q') => return Ok(Some(TuiOutcome::Quit)),
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('/') => {
                self.search_mode = true;
                self.status = "Search mode: type to filter, Enter/Esc to exit".into();
            }
            KeyCode::Enter => self.reveal_selected(store)?,
            KeyCode::Char('y') => self.copy_selected(store)?,
            KeyCode::Char('a') => self.start_add(),
            KeyCode::Char('d') => self.delete_selected(store)?,
            KeyCode::Char('s') => self.toggle_sort(),
            _ => {}
        }

        Ok(None)
    }

    fn handle_ctrl_c(&mut self) -> Option<TuiOutcome> {
        let now = Instant::now();
        if self
            .last_ctrl_c
            .is_some_and(|last| now.duration_since(last) <= self.config.ctrl_c_grace_period)
        {
            return Some(TuiOutcome::Quit);
        }

        self.last_ctrl_c = Some(now);
        self.status = "Press Ctrl+C again to quit".into();
        None
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
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

    fn reveal_selected(&mut self, store: &VaultStore) -> Result<()> {
        let Some(site) = self.selected_site().map(ToOwned::to_owned) else {
            self.status = "No entry selected".into();
            return Ok(());
        };

        self.vault.touch(&site, unix_timestamp()?)?;
        self.persist(store)?;
        self.revealed_site = Some(site.clone());
        self.revealed_until = Some(Instant::now() + self.config.reveal_timeout);
        self.status = format!(
            "Password for {site} revealed for {} seconds",
            self.config.reveal_timeout.as_secs()
        );
        self.refresh_entries();
        Ok(())
    }

    fn copy_selected(&mut self, store: &VaultStore) -> Result<()> {
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
        self.persist(store)?;
        self.clipboard_deadline = Some(Instant::now() + self.config.clipboard_timeout);
        self.status = format!(
            "Copied password for {site}; clipboard will clear in {} seconds",
            self.config.clipboard_timeout.as_secs()
        );
        self.refresh_entries();
        Ok(())
    }

    fn delete_selected(&mut self, store: &VaultStore) -> Result<()> {
        let Some(site) = self.selected_site().map(ToOwned::to_owned) else {
            self.status = "No entry selected".into();
            return Ok(());
        };

        if self.pending_delete_site.as_deref() != Some(site.as_str()) {
            self.pending_delete_site = Some(site.clone());
            self.status = format!("Press d again to delete {site}");
            return Ok(());
        }

        self.pending_delete_site = None;
        self.vault.delete(&site)?;
        self.persist(store)?;
        self.refresh_entries();
        self.status = format!("Deleted {site}");
        Ok(())
    }

    fn start_add(&mut self) {
        self.add_form = Some(AddForm::default());
        self.status = "Add mode: Tab switches fields, Enter saves, Esc cancels".into();
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
        self.pending_delete_site = None;
        if self.filtered_sites.is_empty() {
            self.selected = 0;
            return;
        }

        let len = self.filtered_sites.len() as isize;
        let selected = (self.selected as isize + delta).rem_euclid(len) as usize;
        self.selected = selected;
    }

    fn selected_site(&self) -> Option<&str> {
        self.filtered_sites.get(self.selected).map(String::as_str)
    }

    fn select_site(&mut self, site: &str) {
        if let Some(index) = self.filtered_sites.iter().position(|item| item == site) {
            self.selected = index;
        }
    }

    fn refresh_entries(&mut self) {
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
                let score = site_score.or(username_score)?;
                Some((
                    site.clone(),
                    Some(score),
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
        if self.selected >= self.filtered_sites.len() && !self.filtered_sites.is_empty() {
            self.selected = self.filtered_sites.len() - 1;
        } else if self.filtered_sites.is_empty() {
            self.selected = 0;
        }
    }

    fn expire_timers(&mut self) {
        let now = Instant::now();

        if self.revealed_until.is_some_and(|deadline| now >= deadline) {
            self.revealed_until = None;
            self.revealed_site = None;
            self.status = "Password hidden again".into();
        }

        if self
            .clipboard_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            self.clear_clipboard();
            self.status = "Clipboard cleared".into();
        }
    }

    fn clear_sensitive_state(&mut self) {
        self.revealed_site = None;
        self.revealed_until = None;
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
        store.save(&self.master, &self.vault)
    }

    fn reset_ctrl_c_grace_if_needed(&mut self) {
        if self
            .last_ctrl_c
            .is_some_and(|last| last.elapsed() > self.config.ctrl_c_grace_period)
        {
            self.last_ctrl_c = None;
        }
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
        .constraints([Constraint::Min(0), Constraint::Length(1)])
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

    let status = Paragraph::new(app.status.as_str())
        .alignment(Alignment::Left)
        .style(Style::default().fg(Color::Black).bg(Color::Cyan));
    frame.render_widget(status, layout[1]);

    if let Some(form) = &app.add_form {
        render_add_modal(frame, form);
    }
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
        Paragraph::new("Tab switches fields, Enter saves, Esc cancels")
            .style(Style::default().fg(Color::Gray)),
        inner[3],
    );
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
        "legacy".into()
    } else {
        format!("{timestamp} unix")
    }
}

impl App {
    fn sort_order_label(&self) -> &'static str {
        match self.sort_order {
            SortOrder::Site => "site",
            SortOrder::LastAccessed => "last-accessed",
        }
    }
}
