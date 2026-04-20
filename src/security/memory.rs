use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

pub fn empty_secret() -> SecretString {
    secret_from_string(String::new())
}

pub fn secret_from_string(value: String) -> SecretString {
    SecretString::new(value.into_boxed_str())
}

pub fn push_secret_char(secret: &mut SecretString, ch: char) {
    let mut value = secret.expose_secret().to_owned();
    value.push(ch);
    *secret = secret_from_string(value);
}

pub fn pop_secret_char(secret: &mut SecretString) {
    let mut value = secret.expose_secret().to_owned();
    value.pop();
    *secret = secret_from_string(value);
}

pub fn secret_len(secret: &SecretString) -> usize {
    secret.expose_secret().chars().count()
}

pub fn take_secret(secret: &mut SecretString) -> SecretString {
    std::mem::replace(secret, empty_secret())
}

pub fn wipe_bytes(buffer: &mut Vec<u8>) {
    buffer.zeroize();
    buffer.clear();
}
