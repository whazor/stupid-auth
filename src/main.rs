#[macro_use]
extern crate rocket;
use log::info;
use rocket::State;
use rocket::figment::providers::{Env, Serialized};
use rocket::http::ContentType;
use rocket::{
    form::Form,
    http::Status,
    request::{self, FromRequest, Outcome},
    response::Redirect,
    Request, Response,
};
use rocket::fairing::AdHoc;
use rocket_dyn_templates::tera::Result as TeraResult;
use rocket_dyn_templates::{context, tera::Value, Template};

use rocket::response::{self, Responder};

use rand::Rng;
use rocket::http::CookieJar;
use serde::{Deserialize, Serialize};
use serde_yaml::{from_str, to_string};

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32};
use std::{collections::HashMap, fs, thread, time};

#[cfg(test)]
mod tests;

mod users;
use users::User;
use users::{get_users, Users};

mod passwd;
use passwd::check_password;
use passwd::generate_password;

use crate::users::UserWithSessionID;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[get("/tutorial")]
fn tutorial() -> Template {
    Template::render("tutorial.html", context! {
        post_url: uri!(tutorial_genconfig())
    })
}

#[post("/tutorial", data = "<user>")]
fn tutorial_genconfig(user: Form<User>) -> Template {
    let user = user.into_inner();
    let password = generate_password(user.password.as_bytes());

    if password.is_err() {
        return Template::render(
            "tutorial.html",
            context! {
                config: format!("error: {}", password.err().unwrap()),
                post_url: uri!(tutorial_genconfig())
            },
        );
    }

    let config = to_string(&Users {
        users: vec![User {
            username: user.username,
            password: password.unwrap(),
        }],
    });

    Template::render(
        "tutorial.html",
        context! {
            config: config.unwrap(),
            post_url: uri!(tutorial_genconfig())
        },
    )
}

// get referer
#[get("/login?<rd>&<error>")]
fn login(rd: Option<String>, error: bool, cookies: &CookieJar<'_>) -> Template {
    info!("showing login page, return URL: {:?}", rd);
    // setup csrf token
    let rng = rand::thread_rng();
    let csrf_token: String = rng
        .sample_iter(rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    cookies.add_private(rocket::http::Cookie::new("csrf_token", csrf_token.clone()));

    Template::render(
        "login.html",
        context! {
           post_url: uri!(login_post(rd = rd)),
           error: error,
           csrf_token: csrf_token,
        },
    )
}

#[post("/login?<rd>", data = "<user>")]
fn login_post(
    rd: Option<String>, 
    user: Form<User>, 
    cookies: &CookieJar<'_>, 
    config: &State<AppConfig>, 
    sessions: &State<SessionState>) -> Redirect {
    info!("login post, return URL: {:?}", rd);
    // check csrf token
    let csrf_token = cookies.get_private("csrf_token");
    if csrf_token.is_none() {
        return Redirect::to(uri!(login(rd = rd, error = true)));
    }
    // delete csrf token
    cookies.remove_private(rocket::http::Cookie::named("csrf_token"));

    let users = get_users();
    println!("users: {:?}", users);
    // check if in users
    let mut found = Option::None;

    // add random delay to prevent timing attacks
    let mut rng = rand::thread_rng();
    let delay = rng.gen_range(0..1000);
    thread::sleep(time::Duration::from_millis(delay));

    let user = user.into_inner();
    for u in users.users {
        if u.username == user.username {
            let check = check_password(&u.password, user.password.as_bytes());
            if check.is_ok() {
                found = Option::Some(u);
            }
        }
    }

    if found.is_none() {
        return Redirect::to(uri!(login(rd = rd, error = true)));
    }

    // increase session id    
    let session_id = sessions.last.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // add session id to session
    sessions.store.lock().unwrap().insert(session_id);

    let found = UserWithSessionID {
        user: found.unwrap(),
        session_id: session_id,
    };
    
    cookies.add_private(
        rocket::http::Cookie::build("stupid_auth_user", to_string(&found).unwrap())
            .secure(true)
            .domain(config.domain.clone())
            .finish(),
    );
    // redirect = rd if some and not empty, else "/"
    let backup = "/".to_string();
    let redirect: String = if let Some(rd) = rd {
        if rd.is_empty() || rd == "#" {
            backup
        } else {
            rd
        }
    } else {
        backup
    };
    Redirect::to(redirect)
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

#[get("/public/<file..>")]
fn public(file: std::path::PathBuf) -> Option<(ContentType, Vec<u8>)> {
    match file.to_str() {
        Some("tw.css") => Some((
            ContentType::CSS,
            include_bytes!(env!("TAILWIND_CSS")).to_vec(),
        )),
        Some("tw.css.debug") => Some((ContentType::Text, env!("TAILWIND_CSS").into())),
        _ => None,
    }
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

pub fn hash_public(args: &HashMap<String, Value>) -> TeraResult<Value> {
    let name = args.get("name").expect("name is required");
    let name = name.as_str().expect("name must be a string");
    match name {
        "tw.css" => Ok(include_str!(concat!(env!("TAILWIND_CSS"), ".sha1")).into()),
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
    store: Arc<Mutex<HashSet<u32>>>
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
