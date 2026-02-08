use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::{Cookie, Expiration, PrivateCookieJar};
use log::info;
use rand::{distr::Alphanumeric, Rng};
use serde::Deserialize;
use serde_urlencoded;
use std::{thread, time as std_time};
use tera::Context;
use ::time::{Duration, OffsetDateTime};

use crate::passwd::check_password;
use crate::users::{get_users, UserError, UserWithSessionID};
use crate::{render_template, AppState};

#[derive(Debug, Deserialize)]
pub(crate) struct LoginQuery {
    rd: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginForm {
    username: String,
    password: String,
    csrf_token: Option<String>,
}

fn login_url(rd: Option<&str>, error: Option<UserError>) -> String {
    let mut params: Vec<(&str, String)> = Vec::new();

    if let Some(rd) = rd {
        params.push(("rd", rd.to_string()));
    }

    if let Some(error) = error {
        params.push(("error", error.as_query_value().to_string()));
    }

    if params.is_empty() {
        "/login".to_string()
    } else {
        format!(
            "/login?{}",
            serde_urlencoded::to_string(params).expect("valid query")
        )
    }
}

pub(crate) async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    jar: PrivateCookieJar,
) -> impl IntoResponse {
    info!("showing login page, return URL: {:?}", query.rd);

    let csrf_token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let cookie = Cookie::build(("csrf_token", csrf_token.clone()))
        .expires(Expiration::DateTime(
            OffsetDateTime::now_utc() + Duration::minutes(10),
        ))
        .build();

    let mut context = Context::new();
    context.insert(
        "post_url",
        &login_url(query.rd.as_deref(), None),
    );
    context.insert(
        "error",
        &query.error.and_then(|e| UserError::from_query_value(&e).map(|v| v.to_string())),
    );
    context.insert("csrf_token", &csrf_token);

    (jar.add(cookie), render_template(&state, "login.html", context))
}

pub(crate) async fn login_post(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    jar: PrivateCookieJar,
    Form(user): Form<LoginForm>,
) -> Response {
    info!("login post, return URL: {:?}", query.rd);

    if jar.get("csrf_token").is_none() || user.csrf_token.is_none() {
        return Redirect::to(&login_url(
            query.rd.as_deref(),
            Some(UserError::IncorrectUserPassword),
        ))
        .into_response();
    }

    let mut jar = jar.remove(Cookie::new("csrf_token", ""));

    let users = match get_users() {
        Ok(users) => users,
        Err(error) => {
            return Redirect::to(&login_url(query.rd.as_deref(), Some(error))).into_response();
        }
    };

    let delay = rand::rng().random_range(0..1000);
    thread::sleep(std_time::Duration::from_millis(delay));

    let mut found = None;
    for known_user in users.users {
        if known_user.username == user.username
            && check_password(&known_user.password, user.password.as_bytes()).is_ok()
        {
            found = Some(known_user);
            break;
        }
    }

    let found = match found {
        Some(user) => user,
        None => {
            return Redirect::to(&login_url(
                query.rd.as_deref(),
                Some(UserError::IncorrectUserPassword),
            ))
            .into_response();
        }
    };

    let session_id = state.sessions.last.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    state
        .sessions
        .store
        .lock()
        .expect("session lock")
        .insert(session_id);

    let stored_user = UserWithSessionID {
        user: found,
        session_id,
    };

    let cookie = Cookie::build((
        "stupid_auth_user",
        serde_yaml::to_string(&stored_user).expect("valid yaml"),
    ))
    .secure(true)
    .domain(state.config.domain.clone())
    .expires(Expiration::DateTime(
        OffsetDateTime::now_utc() + Duration::days(i64::from(state.config.cookie_expire)),
    ))
    .build();

    jar = jar.add(cookie);

    let redirect = query
        .rd
        .filter(|val| !val.is_empty() && val != "#")
        .unwrap_or_else(|| "/".to_string());

    (jar, Redirect::to(&redirect)).into_response()
}
