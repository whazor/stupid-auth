use axum::{extract::State, response::Response, Form};
use serde::{Deserialize, Serialize};
use tera::Context;

use crate::{
    passwd::generate_password,
    render_template,
    users::{User, Users},
    AppState,
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct CreateUser {
    pub username: String,
    pub uuid: Option<String>,
    pub password: Option<String>,
}

pub(crate) async fn tutorial(State(state): State<AppState>) -> Response {
    let mut context = Context::new();
    context.insert("post_url", "/tutorial");
    context.insert("username", "");
    context.insert("password", "");
    render_template(&state, "tutorial.html", context)
}

pub(crate) async fn tutorial_genconfig(
    State(state): State<AppState>,
    Form(user): Form<CreateUser>,
) -> Response {
    let password = user
        .password
        .as_ref()
        .map(|p| generate_password(p.as_bytes()).expect("password"));

    let config = serde_yaml::to_string(&Users {
        users: vec![User {
            username: user.username.clone(),
            password: password.expect("password is required"),
        }],
    })
    .expect("valid yaml");

    let mut context = Context::new();
    context.insert("config", &config);
    context.insert("post_url", "/tutorial");
    context.insert("username", &user.username);
    context.insert("password", &user.password);
    render_template(&state, "tutorial.html", context)
}
