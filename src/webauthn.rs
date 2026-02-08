use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ciborium::value::Value;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::io::Cursor;

pub(crate) struct RegistrationResult {
    pub(crate) credential_id: String,
    pub(crate) public_key_cose: String,
    pub(crate) sign_count: u32,
}

pub(crate) struct AuthenticationResult {
    pub(crate) sign_count: u32,
}

struct ParsedClientData {
    ceremony_type: String,
    challenge: String,
}

struct ParsedAuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    credential_id: Option<Vec<u8>>,
    public_key_cose: Option<Vec<u8>>,
}

fn decode_b64url(input: &str) -> Result<Vec<u8>, &'static str> {
    URL_SAFE_NO_PAD
        .decode(input.as_bytes())
        .map_err(|_| "invalid base64url payload")
}

fn parse_client_data(encoded: &str) -> Result<(ParsedClientData, Vec<u8>), &'static str> {
    let raw = decode_b64url(encoded)?;
    let parsed: JsonValue =
        serde_json::from_slice(&raw).map_err(|_| "invalid clientDataJSON payload")?;

    let ceremony_type = parsed
        .get("type")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();
    let challenge = parsed
        .get("challenge")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();

    Ok((
        ParsedClientData {
            ceremony_type,
            challenge,
        },
        raw,
    ))
}

fn parse_auth_data(auth_data: &[u8], expect_attested: bool) -> Result<ParsedAuthData, &'static str> {
    if auth_data.len() < 37 {
        return Err("authenticatorData is too short");
    }

    let mut rp_id_hash = [0_u8; 32];
    rp_id_hash.copy_from_slice(&auth_data[..32]);
    let flags = auth_data[32];
    let sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

    let mut credential_id = None;
    let mut public_key_cose = None;

    if expect_attested {
        if (flags & 0x40) == 0 {
            return Err("authenticatorData is missing attested credential data");
        }

        if auth_data.len() < 55 {
            return Err("authenticatorData attested section is too short");
        }

        let mut index = 37;
        index += 16;

        let cred_len = u16::from_be_bytes([auth_data[index], auth_data[index + 1]]) as usize;
        index += 2;

        if auth_data.len() < index + cred_len {
            return Err("invalid credential id length in authenticatorData");
        }

        let credential_id_bytes = auth_data[index..index + cred_len].to_vec();
        index += cred_len;

        let mut cursor = Cursor::new(&auth_data[index..]);
        let _: Value = ciborium::de::from_reader(&mut cursor)
            .map_err(|_| "invalid COSE key in authenticatorData")?;
        let consumed = cursor.position() as usize;
        if consumed == 0 || auth_data.len() < index + consumed {
            return Err("invalid COSE key length in authenticatorData");
        }

        credential_id = Some(credential_id_bytes);
        public_key_cose = Some(auth_data[index..index + consumed].to_vec());
    }

    Ok(ParsedAuthData {
        rp_id_hash,
        flags,
        sign_count,
        credential_id,
        public_key_cose,
    })
}

fn expected_rp_hash(rp_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    hasher.finalize().into()
}

fn cose_public_key_to_verifying_key(encoded: &str) -> Result<VerifyingKey, &'static str> {
    let bytes = decode_b64url(encoded)?;
    let cose: Value =
        ciborium::de::from_reader(bytes.as_slice()).map_err(|_| "invalid COSE public key")?;

    let map = match cose {
        Value::Map(items) => items,
        _ => return Err("COSE key must be a map"),
    };

    let mut x = None;
    let mut y = None;

    for (key, value) in map {
        let key_int = match key {
            Value::Integer(i) => i128::from(i),
            _ => continue,
        };

        match (key_int, value) {
            (-2, Value::Bytes(bytes)) => x = Some(bytes),
            (-3, Value::Bytes(bytes)) => y = Some(bytes),
            _ => {}
        }
    }

    let x = x.ok_or("COSE key missing x coordinate")?;
    let y = y.ok_or("COSE key missing y coordinate")?;

    if x.len() != 32 || y.len() != 32 {
        return Err("COSE key coordinates must be 32 bytes each");
    }

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| "invalid P-256 public key")
}

pub(crate) fn verify_registration_credential(
    rp_id: &str,
    expected_challenge: &str,
    credential: &JsonValue,
) -> Result<RegistrationResult, &'static str> {
    let response = credential
        .get("response")
        .ok_or("invalid credential payload")?;

    let client_data_json = response
        .get("clientDataJSON")
        .and_then(JsonValue::as_str)
        .ok_or("clientDataJSON is required in credential.response")?;

    let (client_data, _) = parse_client_data(client_data_json)?;
    if client_data.ceremony_type != "webauthn.create" || client_data.challenge != expected_challenge {
        return Err("invalid clientDataJSON challenge or type");
    }

    let attestation_object = response
        .get("attestationObject")
        .and_then(JsonValue::as_str)
        .ok_or("attestationObject is required in credential.response")?;
    let attestation_bytes = decode_b64url(attestation_object)?;
    let attestation_value: Value = ciborium::de::from_reader(attestation_bytes.as_slice())
        .map_err(|_| "invalid attestationObject")?;

    let auth_data_bytes = match attestation_value {
        Value::Map(entries) => entries
            .into_iter()
            .find_map(|(key, value)| match (key, value) {
                (Value::Text(name), Value::Bytes(data)) if name == "authData" => Some(data),
                _ => None,
            })
            .ok_or("attestationObject missing authData")?,
        _ => return Err("attestationObject must be a CBOR map"),
    };

    let parsed_auth = parse_auth_data(&auth_data_bytes, true)?;
    if parsed_auth.rp_id_hash != expected_rp_hash(rp_id) {
        return Err("invalid rpId hash in authenticatorData");
    }

    if (parsed_auth.flags & 0x01) == 0 {
        return Err("user presence flag missing in authenticatorData");
    }

    let raw_id = credential
        .get("rawId")
        .and_then(JsonValue::as_str)
        .or_else(|| credential.get("id").and_then(JsonValue::as_str))
        .ok_or("credential id is missing")?;
    let raw_id_bytes = decode_b64url(raw_id)?;

    if Some(raw_id_bytes.clone()) != parsed_auth.credential_id {
        return Err("credential id mismatch in authenticatorData");
    }

    Ok(RegistrationResult {
        credential_id: raw_id.to_string(),
        public_key_cose: URL_SAFE_NO_PAD.encode(
            parsed_auth
                .public_key_cose
                .ok_or("missing COSE public key in authenticatorData")?,
        ),
        sign_count: parsed_auth.sign_count,
    })
}

pub(crate) fn verify_authentication_assertion(
    rp_id: &str,
    expected_challenge: &str,
    credential: &JsonValue,
    stored_public_key_cose: &str,
) -> Result<AuthenticationResult, &'static str> {
    let response = credential
        .get("response")
        .ok_or("invalid credential payload")?;

    let client_data_json = response
        .get("clientDataJSON")
        .and_then(JsonValue::as_str)
        .ok_or("clientDataJSON is required in credential.response")?;

    let (client_data, client_data_raw) = parse_client_data(client_data_json)?;
    if client_data.ceremony_type != "webauthn.get" || client_data.challenge != expected_challenge {
        return Err("invalid clientDataJSON challenge or type");
    }

    let authenticator_data = response
        .get("authenticatorData")
        .and_then(JsonValue::as_str)
        .ok_or("authenticatorData is required in credential.response")?;
    let authenticator_data_bytes = decode_b64url(authenticator_data)?;

    let parsed_auth = parse_auth_data(&authenticator_data_bytes, false)?;
    if parsed_auth.rp_id_hash != expected_rp_hash(rp_id) {
        return Err("invalid rpId hash in authenticatorData");
    }
    if (parsed_auth.flags & 0x01) == 0 {
        return Err("user presence flag missing in authenticatorData");
    }

    let signature_encoded = response
        .get("signature")
        .and_then(JsonValue::as_str)
        .ok_or("signature is required in credential.response")?;
    let signature_der = decode_b64url(signature_encoded)?;
    let signature = Signature::from_der(&signature_der).map_err(|_| "invalid assertion signature")?;

    let mut message = Vec::with_capacity(authenticator_data_bytes.len() + 32);
    message.extend_from_slice(&authenticator_data_bytes);
    message.extend_from_slice(&Sha256::digest(&client_data_raw));

    let verifying_key = cose_public_key_to_verifying_key(stored_public_key_cose)?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| "assertion signature verification failed")?;

    Ok(AuthenticationResult {
        sign_count: parsed_auth.sign_count,
    })
}
