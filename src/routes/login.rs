use log::info;

use rocket::form::FromForm;
use rocket::State;
use rocket::{form::Form, response::Redirect};
use rocket_dyn_templates::{context, Template};

use rand::Rng;
use rocket::http::CookieJar;

use serde::{Deserialize, Serialize};
use serde_yaml::to_string;
use webauthn_rs::prelude::{PublicKeyCredential, SecurityKey};

use std::{thread, time};

use crate::users::{User, webauthn};
use crate::users::{get_users, UserWithSessionID};
use crate::{AppConfig, SessionState};

use crate::passwd::check_password;

// get referer
#[get("/login?<rd>&<error>")]
pub(crate) fn login(rd: Option<String>, error: bool, cookies: &CookieJar<'_>) -> Template {
    info!("showing login page, return URL: {:?}", rd);
    // setup csrf token
    let rng = rand::thread_rng();
    let csrf_token: String = rng
        .sample_iter(rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    cookies.add_private(rocket::http::Cookie::new("csrf_token", csrf_token.clone()));
    let webauth = webauthn();
    // let creds: Passkey = 

    // webauth.start_passkey_authentication(creds);
    let securitykey = SecurityKey {
        cred: Credential {
            cred_id: "test".to_string(),
            cred: "test".to_string(),
            counter: 0,
            transports: None,
        }
    };
    webauth.start_securitykey_authentication(securitykey);
    Template::render(
        "login.html",
        context! {
           post_url: uri!(login_post(rd = rd)),
           error: error,
           csrf_token: csrf_token,
        },
    )
}

#[derive(Clone, FromForm, Serialize, Deserialize, PartialEq, Debug)]
pub struct Passkey {
    credential: String,
}

#[post("/login-passkey?<rd>", data = "<passkey>")]
pub(crate) fn login_post_passkey(rd: Option<String>, passkey: Form<Passkey>) -> Redirect {
    let cred = passkey.into_inner().credential;
    let cred: PublicKeyCredential = serde_json::from_str(&cred).unwrap();
    println!("cred: {:?}", cred);
    return Redirect::to(uri!(login(rd = rd, error = true)));
}

#[post("/login-seckey?<rd>", data = "<seckey>")]
pub(crate) fn login_post_seckey(rd: Option<String>, seckey: Form<Passkey>) -> Redirect {
    let cred = seckey.into_inner().credential;
    let cred: PublicKeyCredential = serde_json::from_str(&cred).unwrap();
    println!("cred: {:?}", cred);
    return Redirect::to(uri!(login(rd = rd, error = true)));
}

#[post("/login?<rd>", data = "<user>")]
pub(crate) fn login_post(
    rd: Option<String>,
    user: Form<User>,
    cookies: &CookieJar<'_>,
    config: &State<AppConfig>,
    sessions: &State<SessionState>,
) -> Redirect {
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
    let session_id = sessions
        .last
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // add session id to session
    sessions.store.lock().unwrap().insert(session_id);

    let found = UserWithSessionID {
        user: found.unwrap(),
        session_id,
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
