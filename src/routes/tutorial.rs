use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use once_cell::sync::Lazy;
use rand::{distr::Alphanumeric, Rng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use tera::Context;
use time::OffsetDateTime;

use crate::{
    passwd::generate_password,
    render_template,
    users::{get_users, PasskeyUser, User, Users},
    AppState,
};

const REGISTRATION_TTL_SECONDS: i64 = 300;
const MAX_ACTIVE_REGISTRATIONS: usize = 512;

static ACTIVE_REGISTRATIONS: Lazy<Mutex<HashMap<String, ActiveRegistration>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug)]
struct ActiveRegistration {
    username: String,
    challenge: String,
    signing_key_hash: String,
    created_from_users_yaml: bool,
    expires_at: i64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct CreateUser {
    pub username: String,
    pub uuid: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RegisterStartRequest {
    username: String,
    server_signing_key: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterStartResponse {
    token: String,
    public_key_options: PublicKeyCreationOptions,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RegisterFinishRequest {
    token: String,
    credential: JsonValue,
    server_signing_key: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyCreationOptions {
    challenge: String,
    rp: RpEntity,
    user: UserEntity,
    pub_key_cred_params: Vec<PubKeyCredParam>,
    timeout: u64,
    attestation: &'static str,
}

#[derive(Debug, Serialize)]
struct RpEntity {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserEntity {
    id: String,
    name: String,
    display_name: String,
}

#[derive(Debug, Serialize)]
struct PubKeyCredParam {
    alg: i32,
    #[serde(rename = "type")]
    kind: &'static str,
}

fn now_ts() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn random_b64url(bytes: usize) -> String {
    let mut data = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut data);
    URL_SAFE_NO_PAD.encode(data)
}

fn random_signing_key() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn load_server_signing_key() -> Option<String> {
    let users = get_users().ok()?;
    users
        .server_signing_key
        .and_then(|key| if key.is_empty() { None } else { Some(key) })
}

fn resolve_signing_key(client_key: Option<&str>) -> Option<(String, bool)> {
    if let Some(existing_key) = load_server_signing_key() {
        return Some((existing_key, true));
    }

    let provided = client_key?.trim();
    if provided.is_empty() {
        return None;
    }

    Some((provided.to_string(), false))
}

fn cleanup_expired(active: &mut HashMap<String, ActiveRegistration>) {
    let now = now_ts();
    active.retain(|_, entry| entry.expires_at > now);
}

fn header_first_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').next().unwrap_or_default().trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_host(raw: &str) -> String {
    let value = raw.trim();
    if value.starts_with('[') {
        if let Some(end) = value.find(']') {
            return value[1..end].to_string();
        }
    }

    if value.parse::<IpAddr>().is_ok() {
        return value.to_string();
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            return host.to_string();
        }
    }

    value.to_string()
}

fn request_rp_id(headers: &HeaderMap) -> String {
    let host = header_first_value(headers, "x-forwarded-host")
        .or_else(|| header_first_value(headers, "host"))
        .unwrap_or_else(|| "localhost".to_string());
    normalize_host(&host)
}

fn request_is_https(headers: &HeaderMap) -> bool {
    if let Some(proto) = header_first_value(headers, "x-forwarded-proto") {
        return proto.eq_ignore_ascii_case("https");
    }

    if let Some(forwarded) = header_first_value(headers, "forwarded") {
        return forwarded.to_ascii_lowercase().contains("proto=https");
    }

    false
}

fn build_passkey_warnings(headers: &HeaderMap) -> Vec<String> {
    let rp_id = request_rp_id(headers);
    let mut warnings = Vec::new();

    if !request_is_https(headers) {
        warnings.push(
            "Passkeys require HTTPS (except localhost). Use TLS before registering."
                .to_string(),
        );
    }

    if rp_id.parse::<IpAddr>().is_ok() {
        warnings.push(
            "Passkeys are bound to domain RP IDs. Using an IP host can break passkey flows."
                .to_string(),
        );
    }

    warnings
}

fn insert_tutorial_request_context(context: &mut Context, headers: &HeaderMap) {
    context.insert("passkey_warnings", &build_passkey_warnings(headers));
    context.insert("detected_rp_id", &request_rp_id(headers));
}

pub(crate) async fn tutorial(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let mut context = Context::new();
    context.insert("post_url", "/tutorial");
    context.insert("username", "");
    context.insert("password", "");

    let passkey_mode = load_server_signing_key().is_some();
    context.insert("passkey_mode", &passkey_mode);
    insert_tutorial_request_context(&mut context, &headers);

    render_template(&state, "tutorial.html", context)
}

pub(crate) async fn tutorial_genconfig(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(user): Form<CreateUser>,
) -> Response {
    let password = user
        .password
        .as_ref()
        .map(|p| generate_password(p.as_bytes()).expect("password"));

    let config = serde_yaml::to_string(&Users {
        server_signing_key: Some(random_signing_key()),
        users: vec![User {
            username: user.username.clone(),
            password: password.expect("password is required"),
        }],
        passkeys: vec![],
    })
    .expect("valid yaml");

    let mut context = Context::new();
    context.insert("config", &config);
    context.insert("post_url", "/tutorial");
    context.insert("username", &user.username);
    context.insert("password", &user.password);
    context.insert("passkey_mode", &false);
    insert_tutorial_request_context(&mut context, &headers);
    render_template(&state, "tutorial.html", context)
}

pub(crate) async fn tutorial_register_start(
    headers: HeaderMap,
    Json(payload): Json<RegisterStartRequest>,
) -> impl IntoResponse {
    let username = payload.username.trim();
    if username.is_empty() {
        return (StatusCode::BAD_REQUEST, "username is required").into_response();
    }

    let (signing_key, from_users_yaml) =
        match resolve_signing_key(payload.server_signing_key.as_deref()) {
            Some(data) => data,
            None => {
                return (
                    StatusCode::PRECONDITION_FAILED,
                    "server_signing_key is required for first registration",
                )
                    .into_response();
            }
        };

    if signing_key.len() < 32 {
        return (
            StatusCode::BAD_REQUEST,
            "server_signing_key must be at least 32 characters",
        )
            .into_response();
    }

    let token = random_b64url(16);
    let challenge = random_b64url(32);
    let user_id = random_b64url(16);
    let mut active = ACTIVE_REGISTRATIONS.lock().expect("active registrations lock");

    cleanup_expired(&mut active);
    if active.len() >= MAX_ACTIVE_REGISTRATIONS {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many active registration ceremonies",
        )
            .into_response();
    }

    active.insert(
        token.clone(),
        ActiveRegistration {
            username: username.to_string(),
            challenge: challenge.clone(),
            signing_key_hash: sha256::digest(&signing_key),
            created_from_users_yaml: from_users_yaml,
            expires_at: now_ts() + REGISTRATION_TTL_SECONDS,
        },
    );

    Json(RegisterStartResponse {
        token,
        public_key_options: PublicKeyCreationOptions {
            challenge,
            rp: RpEntity {
                id: request_rp_id(&headers),
                name: "stupid-auth".to_string(),
            },
            user: UserEntity {
                id: user_id,
                name: username.to_string(),
                display_name: username.to_string(),
            },
            pub_key_cred_params: vec![PubKeyCredParam {
                alg: -7,
                kind: "public-key",
            }],
            timeout: 60_000,
            attestation: "none",
        },
    })
    .into_response()
}

pub(crate) async fn tutorial_register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterFinishRequest>,
) -> impl IntoResponse {
    let entry = {
        let mut active = ACTIVE_REGISTRATIONS.lock().expect("active registrations lock");
        cleanup_expired(&mut active);
        active.remove(&payload.token)
    };

    let entry = match entry {
        Some(entry) => entry,
        None => return (StatusCode::BAD_REQUEST, "invalid or expired token").into_response(),
    };

    if entry.expires_at <= now_ts() {
        return (StatusCode::BAD_REQUEST, "token expired").into_response();
    }

    let signing_key = if entry.created_from_users_yaml {
        match load_server_signing_key() {
            Some(key) => key,
            None => {
                return (
                    StatusCode::PRECONDITION_FAILED,
                    "server_signing_key in users.yaml changed during ceremony",
                )
                    .into_response();
            }
        }
    } else {
        match payload.server_signing_key.as_deref().map(str::trim) {
            Some(key) if !key.is_empty() => key.to_string(),
            _ => {
                return (
                    StatusCode::PRECONDITION_FAILED,
                    "server_signing_key is required to finish bootstrap registration",
                )
                    .into_response();
            }
        }
    };

    if sha256::digest(&signing_key) != entry.signing_key_hash {
        return (
            StatusCode::BAD_REQUEST,
            "server_signing_key does not match start ceremony",
        )
            .into_response();
    }

    let response = match payload.credential.get("response") {
        Some(value) => value,
        None => return (StatusCode::BAD_REQUEST, "invalid credential payload").into_response(),
    };

    let client_data_json = match response
        .get("clientDataJSON")
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
    {
        Some(value) => value,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "clientDataJSON is required in credential.response",
            )
                .into_response();
        }
    };

    let parsed_client_data = match URL_SAFE_NO_PAD
        .decode(client_data_json.as_bytes())
        .ok()
        .and_then(|raw| serde_json::from_slice::<JsonValue>(&raw).ok())
    {
        Some(value) => value,
        None => return (StatusCode::BAD_REQUEST, "invalid clientDataJSON").into_response(),
    };

    let ceremony_type = parsed_client_data
        .get("type")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    let challenge = parsed_client_data
        .get("challenge")
        .and_then(JsonValue::as_str)
        .unwrap_or("");

    if ceremony_type != "webauthn.create" || challenge != entry.challenge {
        return (
            StatusCode::BAD_REQUEST,
            "invalid clientDataJSON challenge or type",
        )
            .into_response();
    }

    let passkey_entry = PasskeyUser {
        username: entry.username,
        credential_id: payload
            .credential
            .get("id")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_string(),
        raw_id: payload
            .credential
            .get("rawId")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_string(),
        client_data_json,
        attestation_object: response
            .get("attestationObject")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_string(),
        signature: String::new(),
    };

    let body = serde_yaml::to_string(&passkey_entry).expect("valid yaml");
    let signature = sha256::digest(format!("{signing_key}:{body}"));

    let signed_entry = PasskeyUser {
        signature,
        ..passkey_entry
    };

    let append_only_yaml = if entry.created_from_users_yaml {
        format!(
            "passkeys:\n{}",
            serde_yaml::to_string(&vec![signed_entry]).expect("valid yaml")
        )
    } else {
        serde_yaml::to_string(&Users {
            server_signing_key: Some(signing_key),
            users: vec![],
            passkeys: vec![signed_entry],
        })
        .expect("valid yaml")
    };

    let mut context = Context::new();
    context.insert("post_url", "/tutorial");
    context.insert("username", "");
    context.insert("password", "");
    context.insert("passkey_mode", &true);
    context.insert("append_config", &append_only_yaml);
    context.insert("register_result", "Passkey registration is ready. Append this block to users.yaml.");
    insert_tutorial_request_context(&mut context, &headers);

    render_template(&state, "tutorial.html", context)
}
