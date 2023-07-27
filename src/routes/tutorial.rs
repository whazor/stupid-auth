use rocket::form::Form;
use rocket_dyn_templates::{context, Template};

use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use webauthn_rs::prelude::*;

use totp_rs::{Algorithm, Secret, TOTP};

use crate::{passwd::generate_password, users::webauthn};

fn get_qr(random_secret: Secret) -> (String, String) {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        random_secret.to_bytes().unwrap(),
        Some("Github".to_string()),
        "new-user@github.com".to_string(),
    )
    .unwrap();
    (
        totp.get_qr().unwrap(),
        random_secret.to_encoded().to_string(),
    )
}

#[get("/tutorial")]
pub(crate) fn tutorial() -> Template {
    let random_secret = Secret::generate_secret();
    let (totp, totp_secret) = get_qr(random_secret);

    // Now, with the builder you can define other options.
    // Set a "nice" relying party name. Has no security properties and
    // may be changed in the future.

    // Consume the builder and create our webauthn instance.
    let webauthn = webauthn();
    let username = "newuser";
    let user_unique_id = Uuid::new_v4();
    let exclude_credentials = None;

    let res_pass_key = webauthn
        .start_passkey_registration(user_unique_id, username, username, exclude_credentials)
        .expect("Invalid webauthn passkey registration");

    let ccr_passkey = to_string_pretty(&res_pass_key.0).expect("Invalid configuration");
    let reg_state = to_string_pretty(&res_pass_key.1).expect("Invalid configuration");
    let res_sec_key = webauthn
        .start_securitykey_registration(
            user_unique_id, username, username, None, None, None).expect("Invalid webauthn security key registration");
    let ccr_sec_key = to_string_pretty(&res_sec_key.0).expect("Invalid configuration");
    let skr = to_string_pretty(&res_sec_key.1).expect("Invalid configuration");

    Template::render(
        "tutorial.html",
        context! {
            post_url: uri!(tutorial_genconfig()),
            username: "",
            password: "",
            user_unique_id: user_unique_id.to_string(),
            ccr_passkey,
            reg_state,
            ccr_sec_key,
            skr,
            totp,
            totp_secret,
            totp_response: "",
            totp_success: false,
            webauthn: "test",
        },
    )
}

#[derive(Clone, FromForm, Serialize, Deserialize, PartialEq, Debug)]
pub struct CreateUser {
    pub username: String,
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub totp_secret: Option<String>,
    pub webauthn: Option<String>,
}

#[post("/tutorial", data = "<user>")]
pub(crate) fn tutorial_genconfig(user: Form<CreateUser>) -> Template {
    let user = user.into_inner();
    let _password = user
        .password
        .clone()
        .map(|p| generate_password(p.as_bytes()).expect("password"));

    // todo: fix
    // if password.is_some() && password.is_err() {
    //     return Template::render(
    //         "tutorial.html",
    //         context! {
    //             config: format!("error: {}", password.err().unwrap()),
    //             post_url: uri!(tutorial_genconfig())
    //         },
    //     );
    // }

    // let config = to_string(&Users {
    //     users: vec![User {
    //         username: user.clone().username,
    //         password: password,
    //     }],
    // });
    let secret = user.totp_secret.map(Secret::Encoded);
    let (totp, totp_secret) = get_qr(secret.unwrap_or(Secret::generate_secret()));

    Template::render(
        "tutorial.html",
        context! {
            // config: config.unwrap(),
            config: "todo",
            post_url: uri!(tutorial_genconfig()),
            username: user.username,
            password: user.password,
            totp,
            totp_response: "",
            totp_secret,
            totp_success: false,
            webauthn: "test",
        },
    )
}
