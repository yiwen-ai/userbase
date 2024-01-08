use axum::{extract::State, Extension};
use coset::{CborSerializable, CoseKey};
use passkey_types::{
    ctap2::{AuthenticatorData, Flags},
    webauthn::{ClientDataType, CollectedClientData},
};
use public_suffix::{EffectiveTLDProvider, DEFAULT_PROVIDER};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{convert::From, str::FromStr, sync::Arc};
use url::Url;
use validator::Validate;

use axum_web::context::{unix_ms, ReqContext};
use axum_web::erring::{map_bad_request_err, HTTPError, SuccessResponse};
use axum_web::object::PackObject;
use scylla_orm::ColumnsMap;

use super::authn::{AuthNLoginOutput, AuthNOutput};
use crate::api::{self, AppState};
use crate::crypto::{self, base64url_decode};
use crate::db;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ChallengeOutput {
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: String,
    pub challenge: PackObject<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct Challenge {
    pub expire: i64,
    pub nonce: [u8; 12],
}

const CHALLENGE_EXPIRE: i64 = 60 * 5;

impl Challenge {
    pub fn new() -> Self {
        let mut c = Self {
            expire: (unix_ms() / 1000) as i64 + CHALLENGE_EXPIRE,
            nonce: [0u8; 12],
        };
        OsRng.fill_bytes(&mut c.nonce);
        c
    }

    pub fn to_vec(self, ms: &crypto::MacState) -> anyhow::Result<Vec<u8>> {
        ms.create_state(
            crypto::ClaimsSet {
                expiration_time: Some(crypto::Timestamp::WholeSeconds(self.expire)),
                cwt_id: Some(self.nonce.to_vec()),
                ..Default::default()
            },
            b"passkey",
        )
    }

    pub fn verify_slice(data: &[u8], ms: &crypto::MacState) -> anyhow::Result<()> {
        let state = ms.verify_state(data, b"passkey")?;
        let expire = match state.expiration_time {
            Some(crypto::Timestamp::WholeSeconds(t)) => t,
            _ => return Err(anyhow::Error::msg("invalid expiration_time")),
        };
        if expire < (unix_ms() / 1000) as i64 {
            return Err(anyhow::Error::msg("challenge expired"));
        }

        Ok(())
    }
}

pub async fn get_challenge(
    to: PackObject<()>,
    State(app): State<Arc<AppState>>,
) -> Result<PackObject<SuccessResponse<ChallengeOutput>>, HTTPError> {
    let ch = Challenge::new();
    let user_handle = crypto::base64url_encode(&ch.nonce);
    let challenge = ch.to_vec(&app.mac_state)?;
    Ok(to.with(SuccessResponse::new(ChallengeOutput {
        rp_id: app.passkey.rp_id.clone(),
        rp_name: app.passkey.rp_name.clone(),
        user_handle,
        challenge: to.with(challenge),
    })))
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, Validate)]
pub struct RegistrationCredentialInput {
    #[validate(length(min = 16, max = 64))]
    pub id: String,
    #[validate(length(min = 1, max = 64))]
    pub display_name: String,
    pub authenticator_data: PackObject<Vec<u8>>,
    pub client_data: PackObject<Vec<u8>>,
    pub ip: String,
    pub uid: Option<PackObject<xid::Id>>,
}

pub async fn verify_registration(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<RegistrationCredentialInput>,
) -> Result<PackObject<SuccessResponse<AuthNOutput>>, HTTPError> {
    let (to, input) = to.unpack();

    let res: Result<PackObject<SuccessResponse<AuthNOutput>>, HTTPError> = async {
        let input = input.clone();
        input.validate()?;

        let auth = AuthenticatorData::from_slice(&input.authenticator_data)
            .map_err(map_bad_request_err)?;
        let credential = auth.attested_credential_data.ok_or_else(|| {
            HTTPError::new(
                400,
                "invalid authenticator data: missing attested_credential_data".to_string(),
            )
        })?;
        let credential_id = crypto::base64url_decode(&input.id).map_err(map_bad_request_err)?;
        if credential.credential_id() != credential_id {
            return Err(HTTPError::new(
                400,
                "invalid authenticator data: invalid credential_id".to_string(),
            ));
        }

        let payload = credential.key.to_vec().map_err(map_bad_request_err)?;
        let client_data: CollectedClientData =
            serde_json::from_slice(&input.client_data).map_err(map_bad_request_err)?;
        if client_data.ty != ClientDataType::Create {
            return Err(HTTPError::new(
                400,
                "invalid client data: not create type".to_string(),
            ));
        }

        let origin_url = Url::parse(&client_data.origin).map_err(map_bad_request_err)?;
        let mut origin_domain = origin_url
            .domain()
            .ok_or_else(|| HTTPError::new(400, "invalid client data: invalid origin".to_string()))?
            .to_string();

        if origin_domain != "localhost" {
            origin_domain = DEFAULT_PROVIDER
                .effective_tld_plus_one(&origin_domain)
                .unwrap_or_default()
                .to_string();
        }

        let challenge = base64url_decode(&client_data.challenge).map_err(map_bad_request_err)?;
        Challenge::verify_slice(&challenge, &app.mac_state).map_err(map_bad_request_err)?;
        if origin_domain != app.passkey.rp_id {
            return Err(HTTPError::new(
                400,
                "invalid client data: invalid origin".to_string(),
            ));
        }
        let some_uid = input.uid.map(|uid| uid.unwrap());
        let mut doc = db::AuthN::with_pk("pk".to_string(), app.passkey.rp_id.clone(), input.id);
        match doc.get_one(&app.scylla, vec!["uid".to_string()]).await {
            Ok(_) => {
                if some_uid.is_some() && doc.uid != some_uid.unwrap() {
                    return Err(HTTPError::new(
                        401,
                        format!(
                            "Invalid authn, uid not match, expected {}, got {}",
                            some_uid.unwrap(),
                            doc.uid
                        ),
                    ));
                }

                // check user and update
                ctx.set("uid", doc.uid.to_string().into()).await;
                let mut user = db::User::with_pk(doc.uid);
                user.get_one(
                    &app.scylla,
                    vec![
                        "status".to_string(),
                        "rating".to_string(),
                        "kind".to_string(),
                        "name".to_string(),
                        "picture".to_string(),
                    ],
                )
                .await
                .map_err(|e| HTTPError::new(404, format!("Invalid user, {}", e)))?;
                if user.status < -1 {
                    return Err(HTTPError::new(
                        403,
                        format!("{} user, id {}", user.status_name(), user.id),
                    ));
                }

                let mut cols = ColumnsMap::new();
                cols.set_as("ip", &input.ip);
                let _ = doc.update(&app.scylla, cols, doc.uid).await;
            }

            Err(_) => {
                let user = if let Some(uid) = some_uid {
                    ctx.set("uid", uid.to_string().into()).await;
                    let mut user = db::User::with_pk(uid);
                    user.get_one(
                        &app.scylla,
                        vec![
                            "status".to_string(),
                            "rating".to_string(),
                            "kind".to_string(),
                            "name".to_string(),
                            "picture".to_string(),
                        ],
                    )
                    .await
                    .map_err(|e| HTTPError::new(404, format!("Invalid user, {}", e)))?;
                    if user.status < -1 {
                        return Err(HTTPError::new(
                            403,
                            format!("{} user, id {}", user.status_name(), user.id),
                        ));
                    }
                    user
                } else {
                    let new_user = api::user::internal_create(
                        app.clone(),
                        api::user::CreateUserInput {
                            name: input.display_name,
                            locale: to.with(isolang::Language::Eng),
                            picture: None,
                            birthdate: None,
                            gid: None,
                        },
                    )
                    .await?;
                    ctx.set_kvs(vec![
                        ("action", "create_user".into()),
                        ("uid", new_user.id.to_string().into()),
                        ("name", new_user.name.clone().into()),
                    ])
                    .await;
                    new_user
                };

                doc.uid = user.id;
                doc.created_at = user.created_at;
                doc.updated_at = user.updated_at;
                doc.expire_at = doc.updated_at + 1000 * 60 * 60 * 24 * 365 * 99;
                doc.payload = payload;
                doc.save(&app.scylla).await?;
            }
        }

        Ok(to.with(SuccessResponse::new(AuthNOutput {
            idp: doc.idp,
            aud: doc.aud,
            sub: doc.sub,
            uid: to.with(doc.uid),
            ..Default::default()
        })))
    }
    .await;

    if let Err(ref err) = res {
        if let Ok(v) = serde_json::to_value(&input) {
            ctx.set("input", v).await;
        }
        if let Ok(v) = serde_json::to_value(err) {
            ctx.set("error", v).await;
        }
    }

    res
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, Validate)]
pub struct AuthenticationCredentialInput {
    #[validate(length(min = 16, max = 64))]
    pub id: String,
    pub authenticator_data: PackObject<Vec<u8>>,
    pub client_data: PackObject<Vec<u8>>,
    pub signature: PackObject<Vec<u8>>,
    pub ip: String,
    pub device_id: String,
    pub device_desc: String,
}

pub async fn verify_authentication(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<AuthenticationCredentialInput>,
) -> Result<PackObject<SuccessResponse<AuthNLoginOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    let res: Result<PackObject<SuccessResponse<AuthNLoginOutput>>, HTTPError> = async {
        let input = input.clone();
        input.validate()?;

        let auth = AuthenticatorData::from_slice(&input.authenticator_data)
            .map_err(map_bad_request_err)?;
        if !auth.flags.contains(Flags::UP) {
            return Err(HTTPError::new(
                400,
                "invalid authenticator data: userPresent not set".to_string(),
            ));
        }
        if !auth.flags.contains(Flags::UV) {
            return Err(HTTPError::new(
                400,
                "invalid authenticator data: userVerified not set".to_string(),
            ));
        }
        let rp_id_hash = crypto::sha_256(app.passkey.rp_id.as_bytes());
        if auth.rp_id_hash() != rp_id_hash {
            return Err(HTTPError::new(
                400,
                "invalid authenticator data: invalid rp_id_hash".to_string(),
            ));
        }

        let client_data: CollectedClientData =
            serde_json::from_slice(&input.client_data).map_err(map_bad_request_err)?;
        if client_data.ty != ClientDataType::Get {
            return Err(HTTPError::new(
                400,
                "invalid client data: not create type".to_string(),
            ));
        }
        let origin_url = Url::parse(&client_data.origin).map_err(map_bad_request_err)?;
        let mut origin_domain = origin_url
            .domain()
            .ok_or_else(|| HTTPError::new(400, "invalid client data: invalid origin".to_string()))?
            .to_string();

        if origin_domain != "localhost" {
            origin_domain = DEFAULT_PROVIDER
                .effective_tld_plus_one(&origin_domain)
                .unwrap_or_default()
                .to_string();
        }
        if origin_domain != app.passkey.rp_id {
            return Err(HTTPError::new(
                400,
                "invalid client data: invalid origin".to_string(),
            ));
        }

        let challenge = base64url_decode(&client_data.challenge).map_err(map_bad_request_err)?;
        Challenge::verify_slice(&challenge, &app.mac_state).map_err(map_bad_request_err)?;

        ctx.set("id", input.id.clone().into()).await;
        let mut doc = db::AuthN::with_pk("pk".to_string(), app.passkey.rp_id.clone(), input.id);
        doc.get_one(
            &app.scylla,
            vec![
                "uid".to_string(),
                "created_at".to_string(),
                "updated_at".to_string(),
                "payload".to_string(),
            ],
        )
        .await
        .map_err(map_bad_request_err)?;
        let key = CoseKey::from_slice(&doc.payload).map_err(map_bad_request_err)?;
        let mut signed_data: Vec<u8> = Vec::with_capacity(input.authenticator_data.len() + 32);
        signed_data.extend_from_slice(&input.authenticator_data);
        signed_data.extend_from_slice(crypto::sha_256(&input.client_data).as_ref());

        crypto::Key(key)
            .verify_signature(&signed_data, &input.signature)
            .map_err(map_bad_request_err)?;

        ctx.set("uid", doc.uid.to_string().into()).await;
        let mut user = db::User::with_pk(doc.uid);
        user.get_one(
            &app.scylla,
            vec![
                "status".to_string(),
                "rating".to_string(),
                "kind".to_string(),
                "name".to_string(),
                "picture".to_string(),
            ],
        )
        .await
        .map_err(|e| HTTPError::new(404, format!("Invalid user, {}", e)))?;
        if user.status < -1 {
            return Err(HTTPError::new(
                403,
                format!("{} user, id {}", user.status_name(), user.id),
            ));
        }

        if !input.ip.is_empty() {
            let mut cols = ColumnsMap::new();
            cols.set_as("ip", &input.ip);
            let _ = doc.update(&app.scylla, cols, doc.uid).await;
        }
        let mut session: Option<db::Session> = None;
        if !input.device_id.is_empty() {
            if let Ok(existing_sess) = db::Session::find_by_authn(
                &app.scylla,
                doc.uid,
                &input.device_id,
                &doc.idp,
                &doc.aud,
                &doc.sub,
            )
            .await
            {
                let mut existing_sess = existing_sess;
                existing_sess.renew(&app.scylla).await?;
                session = Some(existing_sess);
            }
        }

        let session = match session {
            Some(sess) => sess,
            None => {
                let mut sess = db::Session {
                    id: xid::new(),
                    uid: doc.uid,
                    device_id: input.device_id,
                    device_desc: input.device_desc,
                    idp: doc.idp,
                    aud: doc.aud,
                    sub: doc.sub,
                    ..Default::default()
                };

                if sess.device_id.is_empty() {
                    sess.device_id = sess.id.to_string();
                }
                sess.save(&app.scylla, 0).await?;
                sess
            }
        };

        let jarvis = xid::Id::from_str(db::USER_JARVIS).unwrap();
        let sub = app.mac_id.uuid(&jarvis, &doc.uid);
        let sess = app.session.session(&session.id, &doc.uid, None);
        Ok(to.with(SuccessResponse::new(AuthNLoginOutput {
            sid: to.with(session.id),
            uid: to.with(doc.uid),
            sub: to.with(sub),
            session: sess,
            name: user.name,
            picture: user.picture,
            user_created_at: None,
        })))
    }
    .await;

    if let Err(ref err) = res {
        if let Ok(v) = serde_json::to_value(&input) {
            ctx.set("input", v).await;
        }
        if let Ok(v) = serde_json::to_value(err) {
            ctx.set("error", v).await;
        }
    }

    res
}
