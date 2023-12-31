use log::info;

use rocket::State;
use rocket::time::{OffsetDateTime, Duration};
use rocket::{form::Form, response::Redirect};
use rocket_dyn_templates::{context, Template};

use rand::Rng;
use rocket::http::{CookieJar, Cookie};

use serde_yaml::to_string;

use std::{thread, time};

use crate::users::User;
use crate::users::UserError;
use crate::users::{get_users, UserWithSessionID};
use crate::{AppConfig, SessionState};

use crate::passwd::check_password;

// get referer
#[get("/login?<rd>&<error>")]
pub(crate) fn login(
    rd: Option<String>, 
    error: Option<UserError>,
    cookies: &CookieJar<'_>,
) -> Template {
    info!("showing login page, return URL: {:?}", rd);

    println!("{:?}", error);
    // setup csrf token
    let rng = rand::thread_rng();
    let csrf_token: String = rng
        .sample_iter(rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let mut cookie = rocket::http::Cookie::new("csrf_token", csrf_token.clone());
    let now = OffsetDateTime::now_utc();
    cookie.set_expires(now + Duration::minutes(10));
    cookies.add_private(cookie);
    Template::render(
        "login.html",
        context! {
           post_url: uri!(login_post(rd)),
           error: error.map(|e| e.to_string()),
           csrf_token: csrf_token,
        },
    )
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
        return Redirect::to(uri!(login(rd, Some(UserError::IncorrectUserPassword))));
    }
    // delete csrf token
    cookies.remove_private("csrf_token");

    let users = get_users();
    if users.is_err() {
        return Redirect::to(uri!(login(rd, Some(users.err().unwrap()))))
    }
    let users = users.unwrap();

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
        return Redirect::to(uri!(login(rd, Some(UserError::IncorrectUserPassword))));
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
        Cookie::build(("stupid_auth_user", to_string(&found).unwrap()))
            .secure(true)
            .domain(config.domain.clone())
            .expires(OffsetDateTime::now_utc() + Duration::days(config.cookie_expire.into()))
    );
    // when # or empty, redirect to /
    Redirect::to(
        rd.filter(|val| !val.is_empty() && val != "#")
          .unwrap_or("/".to_string())
    )
}
