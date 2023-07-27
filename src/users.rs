use std::{env, fs};

use serde::{Deserialize, Serialize};
use serde_yaml::from_str;
use webauthn_rs::{prelude::Url, Webauthn, WebauthnBuilder};

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

pub fn get_users() -> Users {
    let current_path = env::current_dir().unwrap();
    let contents =
        fs::read_to_string("./users.yaml").unwrap_or_else(|_| panic!("Cannot read {}/users.yaml, are you sure it exists? Please follow the tutorial at /tutorial and create the file.", current_path.to_str().unwrap()));
    let users: Users = from_str(&contents).unwrap();
    users
}

pub fn webauthn() -> Webauthn {
    let rp_id = "stupid-auth.nanne.dev";
    // Url containing the effective domain name
    // MUST include the port number!
    let rp_origin = Url::parse("https://stupid-auth.nanne.dev").expect("Invalid URL");
    let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid webauthn configuration");
    let builder = builder.rp_name("StupidAuth");
    builder.build().expect("Invalid webauthn builder")
}
