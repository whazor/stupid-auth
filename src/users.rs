use core::fmt;
use std::fs;

use serde::{Deserialize, Serialize};
use serde_yaml::from_str;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct User {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct PasskeyUser {
    pub username: String,
    pub credential_id: String,
    pub raw_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    #[serde(default)]
    pub public_key_cose: String,
    #[serde(default)]
    pub sign_count: u32,
    pub signature: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct UserWithSessionID {
    pub user: User,
    pub session_id: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Users {
    #[serde(default)]
    pub server_signing_key: Option<String>,
    pub users: Vec<User>,
    #[serde(default)]
    pub passkeys: Vec<PasskeyUser>,
}

#[derive(Debug, Clone, Copy)]
pub enum UserError {
    IncorrectUserPassword,
    IOError,
    NoUsersYaml,
    InvalidYaml,
}

impl UserError {
    pub fn as_query_value(&self) -> &'static str {
        match self {
            UserError::IncorrectUserPassword => "incorrect_user_password",
            UserError::IOError => "io_error",
            UserError::NoUsersYaml => "no_users_yaml",
            UserError::InvalidYaml => "invalid_yaml",
        }
    }

    pub fn from_query_value(value: &str) -> Option<Self> {
        match value {
            "incorrect_user_password" => Some(UserError::IncorrectUserPassword),
            "io_error" => Some(UserError::IOError),
            "no_users_yaml" => Some(UserError::NoUsersYaml),
            "invalid_yaml" => Some(UserError::InvalidYaml),
            _ => None,
        }
    }
}

impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UserError::IncorrectUserPassword => {
                write!(f, "Incorrect username or password. Please try again.")
            }
            UserError::IOError => write!(
                f,
                "IO Error. Possible cases:\n            - you are running this program in a directory that does not exist.\n            - you do not have permission to read.\n            - problems with the filesystem.\n            - or something else? check the error message in the logs"
            ),
            UserError::NoUsersYaml => write!(
                f,
                "Cannot read users.yaml, are you sure it exists? Please follow the tutorial at /tutorial and create the file."
            ),
            UserError::InvalidYaml => write!(
                f,
                "Invalid yaml file. Please follow the tutorial at /tutorial and create the correct file."
            ),
        }
    }
}

impl From<std::io::Error> for UserError {
    fn from(error: std::io::Error) -> Self {
        log::error!("IO Error: {}", error);
        match error.kind() {
            std::io::ErrorKind::NotFound => UserError::NoUsersYaml,
            _ => UserError::IOError,
        }
    }
}

impl From<serde_yaml::Error> for UserError {
    fn from(error: serde_yaml::Error) -> Self {
        log::error!("YAML Error: {}", error);
        UserError::InvalidYaml
    }
}

pub fn get_users() -> Result<Users, UserError> {
    let path = std::env::var("AUTH_CONFIG_FILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "users.yaml".to_string());
    let contents = fs::read_to_string(path)?;
    let users: Users = from_str(&contents)?;
    Ok(users)
}
