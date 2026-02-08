#[cfg(test)]
mod test {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
    };
    use ciborium::value::Value as CborValue;
    use http_body_util::BodyExt;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    #[derive(Debug)]
    struct HTMLParser<'a> {
        dom: tl::VDom<'a>,
        main_node: tl::HTMLTag<'a>,
    }

    impl<'a> HTMLParser<'a> {
        pub fn new(input: &'a str) -> Self {
            let error = "Failed to parse HTML";
            let dom = tl::parse(input, tl::ParserOptions::default()).expect(error);
            let main_handle = dom
                .query_selector("html")
                .expect(error)
                .next()
                .expect(error);
            let main_node = main_handle
                .get(dom.parser())
                .expect(error)
                .as_tag()
                .expect(error)
                .clone();
            Self { dom, main_node }
        }

        pub fn find_child(&self, input: tl::HTMLTag<'_>, selector: &str) -> tl::HTMLTag<'_> {
            let binding = format!("Failed to find child with selector: {}", selector);
            let error = binding.as_str();
            let node_handle = input
                .query_selector(self.dom.parser(), selector)
                .expect(error)
                .next()
                .expect(error);
            node_handle
                .get(self.dom.parser())
                .expect(error)
                .as_tag()
                .expect(error)
                .clone()
        }

        pub fn find(&self, selector: &str) -> tl::HTMLTag<'_> {
            self.find_child(self.main_node.clone(), selector)
        }

        pub fn get_attribute(input: tl::HTMLTag, attribute: &str) -> String {
            let binding = format!("Failed to find attribute: {}", attribute);
            let error = binding.as_str();
            let raw: &tl::Bytes<'_> = input
                .attributes()
                .get(attribute)
                .expect(error)
                .expect(error);
            raw.try_as_utf8_str()
                .expect("attribute not utf8")
                .to_string()
        }
    }

    fn decrypt_html_attribute(input: String) -> String {
        input
            .replace("&#x2F;", "/")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    }

    async fn response_text(response: axum::response::Response) -> String {
        String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .expect("read body")
                .to_bytes()
                .to_vec(),
        )
        .expect("utf8 body")
    }

    fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|h| h.to_str().ok())
            .find(|value| value.starts_with(&format!("{name}=")))
            .map(ToString::to_string)
    }

    fn cookie_pair(cookie_header: &str) -> String {
        cookie_header
            .split(';')
            .next()
            .expect("cookie pair")
            .to_string()
    }

    #[tokio::test]
    async fn hello_world() {
        let app = crate::app();
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .expect("request succeeded");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_text(response).await, "Hello, world!");
    }

    #[tokio::test]
    async fn tutorial() {
        let app = crate::app();
        let response = app
            .oneshot(Request::builder().uri("/tutorial").body(Body::empty()).unwrap())
            .await
            .expect("request succeeded");

        assert_eq!(response.status(), StatusCode::OK);

        let output = response_text(response).await;
        assert!(output.contains("Create your first user by filling in the following fields"));
        assert!(output.contains("Passkeys require HTTPS (except localhost)"));
        assert!(output.contains("RP ID"));

        let parser = HTMLParser::new(&output);

        let form = parser.find("form");
        parser.find_child(form.clone(), "input[name=username]");
        parser.find_child(form.clone(), "input[name=password][type=password]");
        parser.find_child(form.clone(), "button[type=submit]");

        let url = decrypt_html_attribute(HTMLParser::get_attribute(form.clone(), "action"));
        assert_eq!(url, "/tutorial");
        let method = HTMLParser::get_attribute(form, "method");
        assert_eq!(method, "POST");
    }

    #[tokio::test]
    async fn tutorial_shows_ip_host_warning() {
        let app = crate::app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/tutorial")
                    .header(header::HOST, "127.0.0.1:8000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request succeeded");

        assert_eq!(response.status(), StatusCode::OK);
        let output = response_text(response).await;
        assert!(output.contains("Using an IP host can break passkey flows"));
    }

    #[tokio::test]
    async fn tutorial_genconfig() {
        let app = crate::app();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tutorial")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("username=foo&password=bar"))
                    .unwrap(),
            )
            .await
            .expect("request succeeded");

        assert_eq!(response.status(), StatusCode::OK);
        let output = response_text(response).await;
        assert!(output.contains("Your config file is ready!"));
        let parser = HTMLParser::new(&output);
        let code = parser.find("pre");
        let text = code
            .children()
            .all(parser.dom.parser())
            .first()
            .expect("valid child");
        let code = text.as_raw().expect("valid raw").as_utf8_str().into_owned();
        let decoded = decrypt_html_attribute(code);

        let config: serde_yaml::Value = serde_yaml::from_str(&decoded).expect("valid yaml");
        let signing_key = config["server_signing_key"]
            .as_str()
            .expect("server signing key");
        assert_eq!(signing_key.len(), 64);
        let users = config["users"].as_sequence().expect("valid sequence");
        assert_eq!(users.len(), 1);
        let user = &users[0];
        assert_eq!(user["username"], "foo");
        let hash = user["password"].as_str().expect("valid string").trim();
        let parsed_hash = PasswordHash::new(hash).expect("valid hash");
        let argon2 = Argon2::default();

        argon2
            .verify_password("bar".as_bytes(), &parsed_hash)
            .expect("valid password");
    }

    #[tokio::test]
    async fn tutorial_register_start_accepts_bootstrap_signing_key() {
        let app = crate::app();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tutorial/register/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"username":"foo","server_signing_key":"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .expect("request succeeded");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn tutorial_register_start_requires_signing_key_when_bootstrapping() {
        let app = crate::app();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tutorial/register/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"username":"foo"}"#))
                    .unwrap(),
            )
            .await
            .expect("request succeeded");

        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn login_start_requires_registered_passkey() {
        let app = crate::app();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"username":"foo","rd":"/"}"#))
                    .unwrap(),
            )
            .await
            .expect("request succeeded");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn webauthn_crypto_registration_and_login_flow() {
        let rp_id = "localhost";
        let register_challenge = "register-challenge";
        let login_challenge = "login-challenge";

        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let verify_key = signing_key.verifying_key();
        let pub_point = verify_key.to_encoded_point(false);
        let x = pub_point.x().expect("x").to_vec();
        let y = pub_point.y().expect("y").to_vec();

        let cose_key = CborValue::Map(vec![
            (CborValue::Integer(1_i64.into()), CborValue::Integer(2_i64.into())),
            (CborValue::Integer(3_i64.into()), CborValue::Integer((-7_i64).into())),
            (CborValue::Integer((-1_i64).into()), CborValue::Integer(1_i64.into())),
            (CborValue::Integer((-2_i64).into()), CborValue::Bytes(x)),
            (CborValue::Integer((-3_i64).into()), CborValue::Bytes(y)),
        ]);
        let mut cose_key_bytes = Vec::new();
        ciborium::ser::into_writer(&cose_key, &mut cose_key_bytes).expect("cose encode");

        let mut credential_id_raw = vec![0_u8; 16];
        rand::rng().fill_bytes(&mut credential_id_raw);
        let credential_id = URL_SAFE_NO_PAD.encode(&credential_id_raw);

        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut reg_auth_data = Vec::new();
        reg_auth_data.extend_from_slice(&rp_hash);
        reg_auth_data.push(0x41);
        reg_auth_data.extend_from_slice(&0_u32.to_be_bytes());
        reg_auth_data.extend_from_slice(&[0_u8; 16]);
        reg_auth_data.extend_from_slice(&(credential_id_raw.len() as u16).to_be_bytes());
        reg_auth_data.extend_from_slice(&credential_id_raw);
        reg_auth_data.extend_from_slice(&cose_key_bytes);

        let attestation_object = CborValue::Map(vec![
            (
                CborValue::Text("fmt".to_string()),
                CborValue::Text("none".to_string()),
            ),
            (
                CborValue::Text("attStmt".to_string()),
                CborValue::Map(vec![]),
            ),
            (
                CborValue::Text("authData".to_string()),
                CborValue::Bytes(reg_auth_data),
            ),
        ]);
        let mut attestation_bytes = Vec::new();
        ciborium::ser::into_writer(&attestation_object, &mut attestation_bytes)
            .expect("attestation encode");

        let reg_client_data_raw = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.create",
            "challenge": register_challenge,
            "origin": "https://localhost"
        }))
        .expect("client data json");
        let registration_credential = serde_json::json!({
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&reg_client_data_raw),
                "attestationObject": URL_SAFE_NO_PAD.encode(&attestation_bytes)
            }
        });

        let registration = crate::webauthn::verify_registration_credential(
            rp_id,
            register_challenge,
            &registration_credential,
        )
        .expect("registration verify");
        assert_eq!(registration.credential_id, credential_id);

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(0x01);
        auth_data.extend_from_slice(&1_u32.to_be_bytes());

        let login_client_data_raw = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": login_challenge,
            "origin": "https://localhost"
        }))
        .expect("client data json");

        let mut signed_payload = Vec::new();
        signed_payload.extend_from_slice(&auth_data);
        signed_payload.extend_from_slice(&Sha256::digest(&login_client_data_raw));

        let signature: Signature = signing_key.sign(&signed_payload);
        let assertion = serde_json::json!({
            "id": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&login_client_data_raw),
                "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
                "signature": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
            }
        });

        let auth = crate::webauthn::verify_authentication_assertion(
            rp_id,
            login_challenge,
            &assertion,
            &registration.public_key_cose,
        )
        .expect("assertion verify");
        assert_eq!(auth.sign_count, 1);
    }

    #[tokio::test]
    async fn login_and_auth() {
        let app = crate::app();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login?rd=https%3A%2F%2Fexample.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request succeeded");

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers().clone();
        let output = response_text(response).await;

        assert!(output.contains("Login"));
        let parser = HTMLParser::new(&output);
        let form = parser.find("form");
        parser.find_child(form.clone(), "input[name=username]");
        parser.find_child(form.clone(), "input[name=password][type=password]");
        let csrf_field = parser.find_child(form.clone(), "input[name=csrf_token]");
        parser.find_child(form.clone(), "button[type=submit]");

        let url = decrypt_html_attribute(HTMLParser::get_attribute(form.clone(), "action"));
        let csrf = decrypt_html_attribute(HTMLParser::get_attribute(csrf_field, "value"));
        assert_eq!(csrf.len(), 32);
        assert_eq!(url, "/login?rd=https%3A%2F%2Fexample.com");
        let method = HTMLParser::get_attribute(form, "method");
        assert_eq!(method, "POST");

        let csrf_cookie = extract_cookie(&headers, "csrf_token").expect("csrf cookie exists");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login?rd=https%3A%2F%2Fexample.com")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, cookie_pair(&csrf_cookie))
                    .body(Body::from(format!(
                        "username={}&password={}&csrf_token={}",
                        "foo", "bar", csrf
                    )))
                    .unwrap(),
            )
            .await
            .expect("request succeeded");

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let headers = response.headers().clone();
        let location = headers
            .get(header::LOCATION)
            .expect("location header")
            .to_str()
            .expect("location utf8");
        assert_eq!(location, "https://example.com");

        let auth_cookie = extract_cookie(&headers, "stupid_auth_user").expect("auth cookie exists");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header(header::COOKIE, cookie_pair(&auth_cookie))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request succeeded");

        assert_eq!(response.status(), StatusCode::OK);
        let user = response
            .headers()
            .get("Remote-User")
            .expect("remote user")
            .to_str()
            .expect("remote user utf8");
        assert_eq!(user, "foo");
        assert_eq!(response_text(response).await, "ok");
    }

    #[tokio::test]
    async fn bad_auth() {
        let app = crate::app();

        let response = app
            .clone()
            .oneshot(Request::builder().uri("/auth").body(Body::empty()).unwrap())
            .await
            .expect("request succeeded");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth")
                    .header(header::COOKIE, "stupid_auth_user=foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request succeeded");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
