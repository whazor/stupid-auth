use rocket::form::Form;
use rocket_dyn_templates::{context, Template};

use serde::{Deserialize, Serialize};

use crate::{passwd::generate_password, users::{User, Users}};
use serde_yaml::to_string;

#[get("/tutorial")]
pub(crate) fn tutorial() -> Template {
    Template::render(
        "tutorial.html",
        context! {
            post_url: uri!(tutorial_genconfig()),
            username: "",
            password: "",
        },
    )
}

#[derive(Clone, FromForm, Serialize, Deserialize, PartialEq, Debug)]
pub struct CreateUser {
    pub username: String,
    pub uuid: Option<String>,
    pub password: Option<String>,
}

#[post("/tutorial", data = "<user>")]
pub(crate) fn tutorial_genconfig(user: Form<CreateUser>) -> Template {
    let user = user.into_inner();
    let password = user
        .password
        .clone()
        .map(|p| generate_password(p.as_bytes()).expect("password"));

    
    let config = to_string(&Users {
        users: vec![User {
            username: user.username.clone(),
            password: password.unwrap(),
        }],
    });

    Template::render(
        "tutorial.html",
        context! {
            config: config.unwrap(),
            post_url: uri!(tutorial_genconfig()),
            username: user.username,
            password: user.password,
        },
    )
}
