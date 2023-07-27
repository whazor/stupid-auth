#[macro_use]
extern crate rocket;
use once_cell::sync::Lazy;
use rocket::fairing::AdHoc;
use rocket::figment::providers::{Env, Serialized};
use rocket::http::ContentType;
use rocket::State;
use rocket::{
    http::Status,
    request::{self, FromRequest, Outcome},
    response::Redirect,
    Request, Response,
};
use rocket_dyn_templates::tera::Result as TeraResult;
use rocket_dyn_templates::{tera::Value, Template};

use rocket::response::{self, Responder};

use rand::Rng;
use rocket::http::CookieJar;
use serde::{Deserialize, Serialize};
use serde_yaml::from_str;

use sha256::digest;
use std::collections::HashSet;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use std::{collections::HashMap, fs};

#[cfg(test)]
mod tests;

mod users;
use users::User;

mod passwd;

mod routes;
use routes::login::{login, login_post};
use routes::tutorial::{tutorial, tutorial_genconfig};

use crate::users::UserWithSessionID;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[derive(Debug)]
struct OriginalURL(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OriginalURL {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        for header in req.headers().iter() {
            println!("{}: {:?}", header.name(), header.value());
        }
        let host = req.headers().get_one("x-forwarded-host");
        let proto = req.headers().get_one("x-forwarded-proto");
        let uri = req.headers().get_one("x-forwarded-uri");

        let full_path: Option<String> =
            if let (Some(host), Some(proto), Some(uri)) = (host, proto, uri) {
                Some(format!("{}://{}{}", proto, host, uri))
            } else {
                None
            };
        match full_path {
            Some(full_path) => Outcome::Success(OriginalURL(full_path)),
            None => Outcome::Success(OriginalURL("".to_string())),
        }
    }
}

struct AuthSuccess {
    user: User,
}

impl<'r> Responder<'r, 'static> for AuthSuccess {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        Response::build_from("ok".respond_to(req)?)
            .raw_header("Remote-User", self.user.username)
            .ok()
    }
}

#[get("/auth")]
fn auth(cookies: &CookieJar<'_>, sessions: &State<SessionState>) -> Result<AuthSuccess, Status> {
    if let Some(user) = cookies.get_private("stupid_auth_user") {
        let user: UserWithSessionID = from_str(user.value()).expect("invalid user");
        let session_id = user.session_id;
        let user = user.user;
        println!("user: {:?}", user.username);
        let store = sessions.store.lock().unwrap();
        if store.contains(&session_id) {
            return Ok(AuthSuccess { user });
        }
    }
    // return 401
    Err(Status::Unauthorized)
}

#[get("/logout")]
fn logout(cookies: &CookieJar<'_>, sessions: &State<SessionState>) -> Redirect {
    if let Some(user) = cookies.get_private("stupid_auth_user") {
        if let Ok(user) = from_str::<UserWithSessionID>(user.value()) {
            let session_id = user.session_id;
            sessions.store.lock().unwrap().remove(&session_id);
        }
    }

    cookies.remove_private(rocket::http::Cookie::named("stupid_auth_user"));
    Redirect::to(uri!(index))
}

static TAILWIND_CSS: &str = include_str!(env!("TAILWIND_CSS"));
static TAILWIND_CSS_SHA1: Lazy<String> = Lazy::new(|| digest(TAILWIND_CSS));

#[get("/public/<file..>")]
fn public(file: std::path::PathBuf) -> Option<(ContentType, Vec<u8>)> {
    match file.to_str() {
        Some("tw.css") => Some((ContentType::CSS, TAILWIND_CSS.as_bytes().to_vec())),
        _ => None,
    }
}

pub fn hash_public(args: &HashMap<String, Value>) -> TeraResult<Value> {
    let name = args.get("name").expect("name is required");
    let name = name.as_str().expect("name must be a string");
    match name {
        "tw.css" => {
            // use static
            Ok(TAILWIND_CSS_SHA1.clone().into())
        }
        _ => Err("unknown file".into()),
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct AppConfig {
    domain: String,
}
impl Default for AppConfig {
    fn default() -> Self {
        Self {
            domain: "localhost".to_string(),
        }
    }
}

struct SessionState {
    last: AtomicU32,
    store: Arc<Mutex<HashSet<u32>>>,
}

#[launch]
fn rocket() -> _ {
    // we load all templates via string, so it doesn't matter where we put them
    fs::create_dir_all("/tmp/templates").unwrap();

    let rng = rand::thread_rng();
    let secret_key = rng
        .sample_iter(rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect::<String>();
    let secret_key: &[u8] = secret_key.as_bytes();

    let config = rocket::Config::figment()
        .merge(Serialized::defaults(AppConfig::default()))
        .merge(("template_dir", "/tmp/templates"))
        .merge(("address", "0.0.0.0"))
        .merge(("secret_key", secret_key))
        .merge(("shutdown.signals", vec!["term", "hup", "int"]))
        .merge(("shutdown.grace", 1))
        .merge(Env::prefixed("AUTH_").global());

    rocket::custom(config)
        .manage(SessionState {
            last: AtomicU32::new(0),
            // store: HashSet::new(),
            store: Arc::new(Mutex::new(HashSet::new())),
        })
        .mount(
            "/",
            routes![
                index,
                public,
                tutorial,
                tutorial_genconfig,
                auth,
                login,
                login_post,
                logout
            ],
        )
        .attach(AdHoc::config::<AppConfig>())
        .attach(Template::custom(|engines| {
            engines
                .tera
                .add_raw_templates(vec![
                    (
                        "_macros.html",
                        include_str!("../templates/_macros.html.tera"),
                    ),
                    ("_base.html", include_str!("../templates/_base.html.tera")),
                    (
                        "tutorial.html",
                        include_str!("../templates/tutorial.html.tera"),
                    ),
                    ("login.html", include_str!("../templates/login.html.tera")),
                ])
                .unwrap();
            engines.tera.register_function("hash_public", hash_public);
        }))
}
