use axum::{
    extract::{FromRef, Path, Request, State},
    http::{header::HeaderName, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::{Cookie, Key, PrivateCookieJar};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::collections::HashSet;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use tera::{Result as TeraResult, Tera, Value};

#[cfg(test)]
mod tests;

mod passwd;
mod routes;
mod users;
mod webauthn;

use routes::login::{login, login_finish, login_post, login_start};
use routes::tutorial::{tutorial, tutorial_genconfig, tutorial_register_finish, tutorial_register_start};
use users::UserWithSessionID;

static TAILWIND_CSS: &str = include_str!(env!("TAILWIND_CSS"));
static TAILWIND_CSS_SHA1: Lazy<String> = Lazy::new(|| digest(TAILWIND_CSS));

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct AppConfig {
    pub(crate) domain: String,
    pub(crate) cookie_expire: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            domain: "localhost".to_string(),
            cookie_expire: 30,
        }
    }
}

impl AppConfig {
    fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(domain) = std::env::var("AUTH_DOMAIN") {
            if !domain.is_empty() {
                config.domain = domain;
            }
        }

        if let Ok(cookie_expire) = std::env::var("AUTH_COOKIE_EXPIRE") {
            if let Ok(parsed) = cookie_expire.parse::<u32>() {
                config.cookie_expire = parsed;
            }
        }

        config
    }
}

struct SessionState {
    last: AtomicU32,
    store: Mutex<HashSet<u32>>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: AppConfig,
    pub(crate) sessions: Arc<SessionState>,
    pub(crate) tera: Arc<Tera>,
    pub(crate) key: Key,
}

impl FromRef<AppState> for Key {
    fn from_ref(input: &AppState) -> Self {
        input.key.clone()
    }
}

struct HashPublicFn;

impl tera::Function for HashPublicFn {
    fn call(&self, args: &std::collections::HashMap<String, Value>) -> TeraResult<Value> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| tera::Error::msg("name is required"))?;

        match name {
            "tw.css" => Ok(TAILWIND_CSS_SHA1.clone().into()),
            _ => Err(tera::Error::msg("unknown file")),
        }
    }
}

fn init_tera() -> Tera {
    let mut tera = Tera::default();
    tera.add_raw_templates(vec![
        ("_macros.html", include_str!("../templates/_macros.html.tera")),
        ("_base.html", include_str!("../templates/_base.html.tera")),
        (
            "tutorial.html",
            include_str!("../templates/tutorial.html.tera"),
        ),
        ("login.html", include_str!("../templates/login.html.tera")),
    ])
    .expect("valid templates");
    tera.register_function("hash_public", HashPublicFn);
    tera
}

fn init_logger() {
    let _ = fern::Dispatch::new()
        .level(log::LevelFilter::Info)
        .chain(std::io::stdout())
        .apply();
}

pub(crate) fn render_template(state: &AppState, template: &str, context: tera::Context) -> Response {
    match state.tera.render(template, &context) {
        Ok(body) => Html(body).into_response(),
        Err(error) => {
            log::error!("template render failed: {error}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Whoops! Looks like we messed up.").into_response()
        }
    }
}

async fn index() -> &'static str {
    "Hello, world!"
}

async fn auth(jar: PrivateCookieJar, State(state): State<AppState>) -> Result<Response, StatusCode> {
    let cookie = jar
        .get("stupid_auth_user")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let user_with_session: UserWithSessionID =
        serde_yaml::from_str(cookie.value()).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let is_valid = {
        let store = state.sessions.store.lock().expect("session lock");
        store.contains(&user_with_session.session_id)
    };

    if !is_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let header_name = HeaderName::from_static("remote-user");
    Ok(([(header_name, user_with_session.user.username)], "ok").into_response())
}

async fn logout(jar: PrivateCookieJar, State(state): State<AppState>) -> impl IntoResponse {
    if let Some(cookie) = jar.get("stupid_auth_user") {
        if let Ok(user) = serde_yaml::from_str::<UserWithSessionID>(cookie.value()) {
            state
                .sessions
                .store
                .lock()
                .expect("session lock")
                .remove(&user.session_id);
        }
    }

    let jar = jar.remove(Cookie::new("stupid_auth_user", ""));
    (jar, Redirect::to("/"))
}

async fn public(Path(file): Path<String>) -> Response {
    if file == "tw.css" {
        return (
            [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
            TAILWIND_CSS,
        )
            .into_response();
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn not_found(request: Request) -> Response {
    (
        StatusCode::NOT_FOUND,
        format!("I couldn't find '{}'. Try something else?", request.uri()),
    )
        .into_response()
}

pub(crate) fn app() -> Router {
    let config = AppConfig::from_env();

    let key = Key::generate();

    let state = AppState {
        config,
        sessions: Arc::new(SessionState {
            last: AtomicU32::new(0),
            store: Mutex::new(HashSet::new()),
        }),
        tera: Arc::new(init_tera()),
        key,
    };

    Router::new()
        .route("/", get(index))
        .route("/public/{*file}", get(public))
        .route("/tutorial", get(tutorial).post(tutorial_genconfig))
        .route("/tutorial/register/start", post(tutorial_register_start))
        .route("/tutorial/register/finish", post(tutorial_register_finish))
        .route("/auth", get(auth))
        .route("/login", get(login).post(login_post))
        .route("/login/start", post(login_start))
        .route("/login/finish", post(login_finish))
        .route("/logout", get(logout))
        .fallback(not_found)
        .with_state(state)
}

#[tokio::main]
async fn main() {
    init_logger();

    let app = app();

    let bind_addr = std::env::var("AUTH_ADDRESS").unwrap_or_else(|_| "0.0.0.0".to_string());
    let bind_port = std::env::var("AUTH_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(8000);
    let listener = tokio::net::TcpListener::bind((bind_addr.as_str(), bind_port))
        .await
        .expect("bind listener");

    axum::serve(listener, app).await.expect("serve app");
}
