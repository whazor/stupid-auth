use core::fmt;
use std::fs;

use rocket::{http::uri::fmt::{FromUriParam, Query}, form::{FromFormField}};
use serde::{Deserialize, Serialize};
use serde_yaml::from_str;

#[derive(Clone, FromForm, Serialize, Deserialize, PartialEq, Debug)]
pub struct User {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct UserWithSessionID {
    pub user: User,
    pub session_id: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Users {
    pub users: Vec<User>,
}

// create errors for: no users.yaml, or invalid yaml file
#[derive(Debug, FromFormField)]
pub enum UserError {
    #[field(value="incorrect_user_password")]
    IncorrectUserPassword,
    #[field(value="io_error")]
    IOError,
    #[field(value="no_users_yaml")]
    NoUsersYaml,
    #[field(value="invalid_yaml")]
    InvalidYaml,
}

 impl FromUriParam<Query, UserError> for UserError {
     type Target = String;

     fn from_uri_param(param: UserError) -> Self::Target {
         // param.into()
        match param {
            UserError::IncorrectUserPassword => "incorrect_user_password".to_string(),
            UserError::IOError => "io_error".to_string(),
            UserError::NoUsersYaml => "no_users_yaml".to_string(),
            UserError::InvalidYaml => "invalid_yaml".to_string(),
        }
     }
 }



impl fmt::Display for UserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UserError::IncorrectUserPassword => write!(f, "Incorrect username or password. Please try again."),
            UserError::IOError => write!(f, "IO Error. Possible cases: 
            - you are running this program in a directory that does not exist.
            - you do not have permission to read.
            - problems with the filesystem.
            - or something else? check the error message in the logs"),
            UserError::NoUsersYaml => write!(f, "Cannot read users.yaml, are you sure it exists? Please follow the tutorial at /tutorial and create the file."),
            UserError::InvalidYaml => write!(f, "Invalid yaml file. Please follow the tutorial at /tutorial and create the correct file."),
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
    let contents = fs::read_to_string("users.yaml")?;
    let users: Users = from_str(&contents)?;
    Ok(users)
}
