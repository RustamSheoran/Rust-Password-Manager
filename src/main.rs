use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fmt, fs,
    io::{self, Write},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(unix)]
use std::process::{Command, Stdio};

const DB_PATH: &str = "db.json";
const MAGIC: &[u8] = b"pmgr1\0";
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Serialize, Deserialize)]
struct Entry {
    username: String,
    password: String,
    created_at: u64,
}

#[derive(Serialize, Deserialize)]
struct Store {
    salt: String,
    check: String,
    data: String,
}

type Db = HashMap<String, Entry>;
type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug)]
enum AppError {
    Io(io::Error),
    Json(serde_json::Error),
    CorruptedJson,
    WrongMaster,
    Missing(String),
    Exists(String),
    Input(&'static str),
    Usage,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Json(e) => write!(f, "{e}"),
            Self::CorruptedJson => write!(f, "corrupted database JSON"),
            Self::WrongMaster => write!(f, "wrong master password"),
            Self::Missing(site) => write!(f, "entry not found: {site}"),
            Self::Exists(site) => write!(f, "entry already exists: {site} (use --force to overwrite)"),
            Self::Input(msg) => write!(f, "{msg}"),
            Self::Usage => write!(f, "usage: add <site> [--force] | get <site> | list"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<io::Error> for AppError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [cmd, site] if cmd == "add" => add(site, false),
        [cmd, flag, site] if cmd == "add" && is_force(flag) => add(site, true),
        [cmd, site, flag] if cmd == "add" && is_force(flag) => add(site, true),
        [cmd, site] if cmd == "get" => get(site),
        [cmd] if cmd == "list" => list(),
        _ => Err(AppError::Usage),
    }
}

fn add(site: &str, force: bool) -> Result<()> {
    let master = master_password()?;
    let (mut db, salt) = load(&master)?;
    if !force && db.contains_key(site) {
        return Err(AppError::Exists(site.to_owned()));
    }
    let username = prompt("Username: ", false)?;
    let password = prompt("Password: ", true)?;
    let created_at = db.get(site).map_or(now()?, |entry| entry.created_at);
    db.insert(site.to_owned(), Entry { username, password, created_at });
    save(&master, &salt, &db)
}

fn get(site: &str) -> Result<()> {
    let master = master_password()?;
    let (db, _) = load(&master)?;
    let entry = db.get(site).ok_or_else(|| AppError::Missing(site.to_owned()))?;
    println!("username: {}\npassword: {}", entry.username, entry.password);
    Ok(())
}

fn list() -> Result<()> {
    let master = master_password()?;
    let (db, _) = load(&master)?;
    let mut sites = db.keys().map(String::as_str).collect::<Vec<_>>();
    sites.sort_unstable();
    for site in sites {
        println!("{site}");
    }
    Ok(())
}

fn master_password() -> Result<String> {
    let master = prompt("Master password: ", true)?;
    if master.is_empty() {
        return Err(AppError::Input("master password cannot be empty"));
    }
    Ok(master)
}

fn prompt(label: &str, secret: bool) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let hidden = secret && set_echo(false);
    let mut s = String::new();
    let read = io::stdin().read_line(&mut s);
    if hidden {
        let _ = set_echo(true);
        println!();
    }
    read?;
    while matches!(s.as_bytes().last().copied(), Some(b'\n' | b'\r')) {
        s.pop();
    }
    Ok(s)
}

#[cfg(unix)]
fn set_echo(on: bool) -> bool {
    Command::new("stty")
        .arg(if on { "echo" } else { "-echo" })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .is_some_and(|status| status.success())
}

#[cfg(not(unix))]
fn set_echo(_: bool) -> bool { false }

fn load(master: &str) -> Result<(Db, [u8; 16])> {
    let raw = match fs::read_to_string(DB_PATH) {
        Ok(raw) => raw,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((HashMap::new(), new_salt()?)),
        Err(e) => return Err(e.into()),
    };
    if raw.trim().is_empty() {
        return Ok((HashMap::new(), new_salt()?));
    }
    let store: Store = serde_json::from_str(&raw).map_err(|_| AppError::CorruptedJson)?;
    let salt = decode_fixed::<16>(&store.salt).ok_or(AppError::CorruptedJson)?;
    let key = derive_key(master.as_bytes(), &salt);
    if encode_hex(&tag(&key, &salt)) != store.check {
        return Err(AppError::WrongMaster);
    }
    let mut data = decode_hex(&store.data).ok_or(AppError::CorruptedJson)?;
    crypt(&mut data, &key, &salt);
    let plain = data.strip_prefix(MAGIC).ok_or(AppError::CorruptedJson)?;
    Ok((serde_json::from_slice(plain).map_err(|_| AppError::CorruptedJson)?, salt))
}

fn save(master: &str, salt: &[u8; 16], db: &Db) -> Result<()> {
    let key = derive_key(master.as_bytes(), salt);
    let mut data = Vec::with_capacity(MAGIC.len() + db.len() * 64);
    data.extend_from_slice(MAGIC);
    serde_json::to_writer(&mut data, db).map_err(AppError::Json)?;
    crypt(&mut data, &key, salt);
    let store = Store {
        salt: encode_hex(salt),
        check: encode_hex(&tag(&key, salt)),
        data: encode_hex(&data),
    };
    fs::write(DB_PATH, serde_json::to_vec(&store).map_err(AppError::Json)?)?;
    Ok(())
}

fn derive_key(master: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut s = 0xcbf29ce484222325u64 ^ u64_from(&salt[..8]) ^ u64_from(&salt[8..]).rotate_left(32);
    for _ in 0..2048 {
        if master.is_empty() {
            s = mix64(s ^ 0xff);
        } else {
            for &b in master {
                s = mix64((s ^ u64::from(b)).wrapping_mul(0x100000001b3));
            }
        }
        for &b in salt {
            s = mix64((s ^ u64::from(b)).wrapping_mul(0x100000001b3));
        }
    }
    let mut out = [0; 32];
    for chunk in out.chunks_mut(8) {
        s = mix64(s ^ 0x9e3779b97f4a7c15);
        chunk.copy_from_slice(&s.to_le_bytes());
    }
    out
}

fn crypt(data: &mut [u8], key: &[u8; 32], salt: &[u8; 16]) {
    let mut s = u64_from(&key[..8])
        ^ u64_from(&key[8..16]).rotate_left(13)
        ^ u64_from(&key[16..24]).rotate_left(27)
        ^ u64_from(&key[24..32]).rotate_left(39)
        ^ u64_from(&salt[..8]).rotate_left(7)
        ^ u64_from(&salt[8..]).rotate_left(29);
    for chunk in data.chunks_mut(8) {
        s = mix64(s ^ 0x9e3779b97f4a7c15);
        let block = s.to_le_bytes();
        for (byte, mask) in chunk.iter_mut().zip(block) {
            *byte ^= mask;
        }
    }
}

fn tag(key: &[u8; 32], salt: &[u8; 16]) -> [u8; 16] {
    let a = mix64(
        u64_from(&key[..8]) ^ u64_from(&key[16..24]).rotate_left(17) ^ u64_from(&salt[..8]).rotate_left(7),
    );
    let b = mix64(
        u64_from(&key[8..16]) ^ u64_from(&key[24..32]).rotate_left(23) ^ u64_from(&salt[8..]).rotate_left(11),
    );
    let mut out = [0; 16];
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

fn new_salt() -> Result<[u8; 16]> {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?;
    let mut s = t.as_secs() ^ (t.as_nanos() as u64).rotate_left(17) ^ u64::from(std::process::id()).rotate_left(33);
    let mut out = [0; 16];
    for chunk in out.chunks_mut(8) {
        s = mix64(s ^ 0x517cc1b727220a95);
        chunk.copy_from_slice(&s.to_le_bytes());
    }
    Ok(out)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_secs())
}

fn u64_from(bytes: &[u8]) -> u64 {
    let mut out = [0; 8];
    out.copy_from_slice(bytes);
    u64::from_le_bytes(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

fn decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let out = decode_hex(s)?;
    if out.len() != N {
        return None;
    }
    let mut fixed = [0; N];
    fixed.copy_from_slice(&out);
    Some(fixed)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        out.push((hex_val(bytes[i])? << 4) | hex_val(bytes[i + 1])?);
        i += 2;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

fn is_force(flag: &str) -> bool {
    matches!(flag, "-f" | "--force")
}
