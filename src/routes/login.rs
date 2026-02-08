use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form, Json,
};
use axum_extra::extract::cookie::{Cookie, Expiration, PrivateCookieJar};
use log::info;
use once_cell::sync::Lazy;
use rand::{distr::Alphanumeric, Rng};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_urlencoded;
use std::collections::HashMap;
use std::sync::Mutex;
use std::{thread, time as std_time};
use tera::Context;
use ::time::{Duration, OffsetDateTime};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use url::Url;

use crate::passwd::check_password;
use crate::users::{get_users, User, UserError, UserWithSessionID};
use crate::webauthn::verify_authentication_assertion;
use crate::{render_template, AppState};

const LOGIN_TTL_SECONDS: i64 = 300;
const MAX_ACTIVE_LOGINS: usize = 512;

static ACTIVE_LOGIN_CHALLENGES: Lazy<Mutex<HashMap<String, ActiveLoginChallenge>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug)]
struct ActiveLoginChallenge {
    username: String,
    challenge: String,
    redirect: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginQuery {
    rd: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginForm {
    username: Option<String>,
    password: Option<String>,
    csrf_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginStartRequest {
    username: String,
    rd: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LoginFinishRequest {
    token: String,
    credential: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginStartResponse {
    token: String,
    assertion_options: PublicKeyRequestOptions,
}

#[derive(Debug, Serialize)]
pub(crate) struct LoginFinishResponse {
    ok: bool,
    redirect_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyRequestOptions {
    challenge: String,
    timeout: u64,
    rp_id: String,
    allow_credentials: Vec<AllowedCredential>,
    user_verification: &'static str,
}

#[derive(Debug, Serialize)]
struct AllowedCredential {
    #[serde(rename = "type")]
    kind: &'static str,
    id: String,
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

fn validate_redirect(rd: Option<String>, allowed_host: &str) -> Result<Option<String>, UserError> {
    let rd = match rd {
        Some(value) => value.trim().to_string(),
        None => return Ok(None),
    };

    if rd.is_empty() || rd == "#" {
        return Ok(None);
    }

    if rd.starts_with('/') && !rd.starts_with("//") {
        return Ok(Some(rd));
    }

    let parsed = Url::parse(&rd).map_err(|_| UserError::InvalidReturnUrl)?;
    let host = parsed
        .host_str()
        .ok_or(UserError::InvalidReturnUrl)?
        .to_ascii_lowercase();
    let allowed = allowed_host.trim().trim_end_matches('.').to_ascii_lowercase();
    let is_allowed = host == allowed || host.ends_with(&format!(".{allowed}"));
    if !is_allowed {
        return Err(UserError::InvalidReturnUrl);
    }

    Ok(Some(rd))
}

fn now_ts() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn random_b64url(bytes: usize) -> String {
    let mut data = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut data);
    URL_SAFE_NO_PAD.encode(data)
}

fn login_redirect(rd: Option<String>) -> String {
    rd.filter(|val| !val.is_empty() && val != "#")
        .unwrap_or_else(|| "/".to_string())
}

fn request_rp_id(headers: &HeaderMap) -> String {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("localhost");

    if let Some(host_no_port) = host.strip_prefix('[').and_then(|v| v.split(']').next()) {
        return host_no_port.to_string();
    }

    if let Some((base, port)) = host.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            return base.to_string();
        }
    }

    host.to_string()
}

fn issue_auth_cookie(state: &AppState, jar: PrivateCookieJar, user: User) -> PrivateCookieJar {
    let session_id = state
        .sessions
        .last
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    state
        .sessions
        .store
        .lock()
        .expect("session lock")
        .insert(session_id);

    let stored_user = UserWithSessionID { user, session_id };
    let cookie = Cookie::build((
        "stupid_auth_user",
        serde_yaml::to_string(&stored_user).expect("valid yaml"),
    ))
    .secure(true)
    .path("/")
    .domain(state.config.domain.clone())
    .expires(Expiration::DateTime(
        OffsetDateTime::now_utc() + Duration::days(i64::from(state.config.cookie_expire)),
    ))
    .build();

    jar.add(cookie)
}

pub(crate) async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    jar: PrivateCookieJar,
) -> impl IntoResponse {
    info!("showing login page, return URL: {:?}", query.rd);

    let had_rd = query.rd.is_some();
    let validated_rd = validate_redirect(query.rd, &state.config.domain).unwrap_or_default();
    let query_error = query
        .error
        .and_then(|e| UserError::from_query_value(&e));
    let error = if had_rd && validated_rd.is_none() {
        Some(UserError::InvalidReturnUrl)
    } else {
        query_error
    };

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
        &login_url(validated_rd.as_deref(), None),
    );
    context.insert(
        "error",
        &error.map(|v| v.to_string()),
    );
    context.insert("csrf_token", &csrf_token);
    context.insert("login_rd", &login_redirect(validated_rd.clone()));

    let (show_password_login, show_passkey_login, no_users_configured) = match get_users() {
        Ok(users) => {
            let has_password_users = !users.users.is_empty();
            let has_passkey_users = !users.passkeys.is_empty();
            (
                has_password_users,
                has_passkey_users,
                !has_password_users && !has_passkey_users,
            )
        }
        Err(_) => (false, false, true),
    };
    context.insert("show_password_login", &show_password_login);
    context.insert("show_passkey_login", &show_passkey_login);
    context.insert("no_users_configured", &no_users_configured);

    (jar.add(cookie), render_template(&state, "login.html", context))
}

pub(crate) async fn login_post(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    jar: PrivateCookieJar,
    Form(user): Form<LoginForm>,
) -> Response {
    info!("login post, return URL: {:?}", query.rd);

    let rd = match validate_redirect(query.rd, &state.config.domain) {
        Ok(value) => value,
        Err(error) => return Redirect::to(&login_url(None, Some(error))).into_response(),
    };

    if jar.get("csrf_token").is_none() || user.csrf_token.is_none() {
        return Redirect::to(&login_url(
            rd.as_deref(),
            Some(UserError::IncorrectUserPassword),
        ))
        .into_response();
    }

    let username = user.username.unwrap_or_default();
    let password = user.password.unwrap_or_default();
    if username.is_empty() || password.is_empty() {
        return Redirect::to(&login_url(
            rd.as_deref(),
            Some(UserError::IncorrectUserPassword),
        ))
        .into_response();
    }

    let mut jar = jar.remove(Cookie::new("csrf_token", ""));

    let users = match get_users() {
        Ok(users) => users,
        Err(error) => {
            return Redirect::to(&login_url(rd.as_deref(), Some(error))).into_response();
        }
    };

    let delay = rand::rng().random_range(0..1000);
    thread::sleep(std_time::Duration::from_millis(delay));

    let mut found = None;
    for known_user in users.users {
        if known_user.username == username && check_password(&known_user.password, password.as_bytes()).is_ok()
        {
            found = Some(known_user);
            break;
        }
    }

    let found = match found {
        Some(user) => user,
        None => {
            return Redirect::to(&login_url(
                rd.as_deref(),
                Some(UserError::IncorrectUserPassword),
            ))
            .into_response();
        }
    };

    jar = issue_auth_cookie(&state, jar, found);
    let redirect = login_redirect(rd);

    (jar, Redirect::to(&redirect)).into_response()
}

pub(crate) async fn login_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginStartRequest>,
) -> impl IntoResponse {
    let username = payload.username.trim();
    if username.is_empty() {
        return (StatusCode::BAD_REQUEST, "username is required").into_response();
    }

    let users = match get_users() {
        Ok(users) => users,
        Err(_) => return (StatusCode::BAD_REQUEST, "unable to load users config").into_response(),
    };

    let allow_credentials: Vec<AllowedCredential> = users
        .passkeys
        .iter()
        .filter(|entry| entry.username == username)
        .map(|entry| AllowedCredential {
            kind: "public-key",
            id: entry.credential_id.clone(),
        })
        .collect();

    if allow_credentials.is_empty() {
        return (StatusCode::UNAUTHORIZED, "no passkey registered for this user").into_response();
    }

    let token = random_b64url(16);
    let challenge = random_b64url(32);
    let redirect = match validate_redirect(payload.rd, &state.config.domain) {
        Ok(value) => login_redirect(value),
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid return url").into_response(),
    };
    let mut active = ACTIVE_LOGIN_CHALLENGES
        .lock()
        .expect("active login challenges lock");
    active.retain(|_, entry| entry.expires_at > now_ts());

    if active.len() >= MAX_ACTIVE_LOGINS {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many active login ceremonies",
        )
            .into_response();
    }

    active.insert(
        token.clone(),
        ActiveLoginChallenge {
            username: username.to_string(),
            challenge: challenge.clone(),
            redirect,
            expires_at: now_ts() + LOGIN_TTL_SECONDS,
        },
    );

    Json(LoginStartResponse {
        token,
        assertion_options: PublicKeyRequestOptions {
            challenge,
            timeout: 60_000,
            rp_id: request_rp_id(&headers),
            allow_credentials,
            user_verification: "preferred",
        },
    })
    .into_response()
}

pub(crate) async fn login_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: PrivateCookieJar,
    Json(payload): Json<LoginFinishRequest>,
) -> impl IntoResponse {
    let challenge_entry = {
        let mut active = ACTIVE_LOGIN_CHALLENGES
            .lock()
            .expect("active login challenges lock");
        active.retain(|_, entry| entry.expires_at > now_ts());
        active.remove(&payload.token)
    };

    let challenge_entry = match challenge_entry {
        Some(entry) => entry,
        None => return (StatusCode::BAD_REQUEST, "invalid or expired login token").into_response(),
    };

    if challenge_entry.expires_at <= now_ts() {
        return (StatusCode::BAD_REQUEST, "login token expired").into_response();
    }

    let credential_id = payload
        .credential
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if credential_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "credential id is missing").into_response();
    }

    let users = match get_users() {
        Ok(users) => users,
        Err(_) => return (StatusCode::BAD_REQUEST, "unable to load users config").into_response(),
    };

    let passkey_entry = users.passkeys.iter().find(|entry| {
        entry.username == challenge_entry.username && entry.credential_id == credential_id
    });
    let passkey_entry = match passkey_entry {
        Some(entry) => entry,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                "passkey not registered for this user",
            )
                .into_response()
        }
    };

    let rp_id = request_rp_id(&headers);
    let auth_result = match verify_authentication_assertion(
        &rp_id,
        &challenge_entry.challenge,
        &payload.credential,
        &passkey_entry.public_key_cose,
    ) {
        Ok(result) => result,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };

    if passkey_entry.sign_count > 0
        && auth_result.sign_count > 0
        && auth_result.sign_count <= passkey_entry.sign_count
    {
        return (
            StatusCode::UNAUTHORIZED,
            "assertion sign count did not increase",
        )
            .into_response();
    }

    let user = users
        .users
        .iter()
        .find(|user| user.username == challenge_entry.username)
        .cloned()
        .unwrap_or(User {
            username: challenge_entry.username.clone(),
            password: String::new(),
        });

    let jar = issue_auth_cookie(&state, jar, user);
    (
        jar,
        Json(LoginFinishResponse {
            ok: true,
            redirect_url: challenge_entry.redirect,
        }),
    )
        .into_response()
}
