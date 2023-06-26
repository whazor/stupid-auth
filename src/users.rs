use std::{env, fs};

use serde::{Deserialize, Serialize};
use serde_yaml::from_str;

#[derive(FromForm, Serialize, Deserialize, PartialEq, Debug)]
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

pub fn get_users() -> Users {
    let current_path = env::current_dir().unwrap();
    let contents =
        fs::read_to_string("./users.yaml").unwrap_or_else(|_| panic!("Cannot read {}/users.yaml, are you sure it exists? Please follow the tutorial at /tutorial and create the file.", current_path.to_str().unwrap()));
    let users: Users = from_str(&contents).unwrap();
    users
}
