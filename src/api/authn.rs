use axum::{
    extract::{Query, State},
    Extension,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, convert::From, sync::Arc};
use validator::Validate;

use axum_web::context::{unix_ms, ReqContext};
use axum_web::erring::{HTTPError, SuccessResponse};
use axum_web::object::PackObject;
use scylla_orm::ColumnsMap;

use crate::api::AppState;

use crate::db;

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct AuthNInput {
    #[validate(length(min = 3, max = 10))]
    pub idp: String,
    #[validate(length(min = 3, max = 40))]
    pub aud: String,
    #[validate(length(min = 3, max = 60))]
    pub sub: String,
    pub uid: PackObject<xid::Id>,
    pub expires_in: i32,
    pub scope: HashSet<String>,
    pub ip: String,
    pub payload: PackObject<Vec<u8>>,
    pub device_id: String,
    pub device_desc: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct AuthNLoginOutput {
    pub sid: PackObject<xid::Id>,
    pub uid: PackObject<xid::Id>,
    pub session: String,
}

pub async fn login_or_new(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<AuthNInput>,
) -> Result<PackObject<SuccessResponse<AuthNLoginOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let uid = input.uid.unwrap();
    let expire_at: i64 = unix_ms() as i64 + input.expires_in as i64;
    ctx.set_kvs(vec![
        ("action", "login_or_new".into()),
        ("idp", input.idp.clone().into()),
        ("aud", input.aud.clone().into()),
        ("sub", input.sub.clone().into()),
        ("uid", uid.to_string().into()),
    ])
    .await;

    let mut user = db::User::with_pk(uid);
    user.get_one(
        &app.scylla,
        vec![
            "status".to_string(),
            "rating".to_string(),
            "kind".to_string(),
        ],
    )
    .await
    .map_err(|e| HTTPError::new(404, format!("Invalid user, {}", e)))?;
    if user.status < 0 {
        return Err(HTTPError::new(
            403,
            format!("{} user, id {}", user.status_name(), user.id),
        ));
    }

    let mut doc = db::AuthN::with_pk(input.idp.clone(), input.aud.clone(), input.sub.clone());
    match doc.get_one(&app.scylla, vec!["uid".to_string()]).await {
        Ok(_) => {
            // update
            if doc.uid != uid {
                return Err(HTTPError::new(
                    409,
                    format!(
                        "Invalid authorization, uid not match, expected {}, got {}",
                        doc.uid, uid
                    ),
                ));
            }
            let mut cols = ColumnsMap::new();
            cols.set_as("expire_at", &expire_at);
            cols.set_as("scope", &input.scope);
            cols.set_as("ip", &input.ip);
            cols.set_as("payload", &input.payload.unwrap());
            let _ = doc.update(&app.scylla, cols, uid).await;
        }
        Err(_) => {
            doc.uid = uid;
            doc.expire_at = expire_at;
            doc.scope = input.scope;
            doc.ip = input.ip.clone();
            doc.payload = input.payload.unwrap();
            doc.save(&app.scylla).await?;
        }
    };

    let mut session = db::Session {
        id: xid::new(),
        uid,
        device_id: input.device_id,
        device_desc: input.device_desc,
        idp: input.idp,
        aud: input.aud,
        sub: input.sub,
        ..Default::default()
    };

    session.save(&app.scylla, input.expires_in).await?;
    let sess = app.session.session(&session.id, &uid, None);
    Ok(to.with(SuccessResponse::new(AuthNLoginOutput {
        sid: to.with(session.id),
        uid: to.with(uid),
        session: sess,
    })))
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct AuthNOutput {
    pub idp: String,
    pub aud: String,
    pub sub: String,
    pub uid: PackObject<xid::Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<HashSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<PackObject<Vec<u8>>>,
}

impl AuthNOutput {
    pub fn from<T>(val: db::AuthN, to: &PackObject<T>) -> Self {
        let mut rt = Self {
            idp: val.idp,
            aud: val.aud,
            sub: val.sub,
            uid: to.with(val.uid),
            ..Default::default()
        };

        for v in val._fields {
            match v.as_str() {
                "created_at" => rt.created_at = Some(val.created_at),
                "updated_at" => rt.updated_at = Some(val.updated_at),
                "expire_at" => rt.expire_at = Some(val.expire_at),
                "scope" => rt.scope = Some(val.scope.to_owned()),
                "ip" => rt.ip = Some(val.ip.to_owned()),
                "payload" => rt.payload = Some(to.with(val.payload.to_owned())),
                _ => {}
            }
        }

        rt
    }
}

pub async fn list(
    to: PackObject<()>,
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
) -> Result<PackObject<SuccessResponse<Vec<AuthNOutput>>>, HTTPError> {
    ctx.set_kvs(vec![
        ("action", "list_authn".into()),
        ("uid", ctx.user.to_string().into()),
    ])
    .await;
    let res = db::AuthN::list_by_uid(&app.scylla, ctx.user, vec![]).await?;
    Ok(to.with(SuccessResponse {
        total_size: None,
        next_page_token: None,
        result: res
            .iter()
            .map(|r| AuthNOutput::from(r.to_owned(), &to))
            .collect(),
    }))
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct AuthNPKInput {
    #[validate(length(min = 3, max = 10))]
    pub idp: String,
    #[validate(length(min = 3, max = 40))]
    pub aud: String,
    #[validate(length(min = 3, max = 60))]
    pub sub: String,
    pub fields: Option<String>,
}

pub async fn delete(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<()>,
    input: Query<AuthNPKInput>,
) -> Result<PackObject<SuccessResponse<bool>>, HTTPError> {
    input.validate()?;

    ctx.set_kvs(vec![
        ("action", "delete_authn".into()),
        ("idp", input.idp.clone().into()),
        ("aud", input.aud.clone().into()),
        ("sub", input.sub.clone().into()),
        ("uid", ctx.user.to_string().into()),
    ])
    .await;

    let mut doc = db::AuthN::with_pk(input.idp.clone(), input.aud.clone(), input.sub.clone());
    let res = doc.delete(&app.scylla, ctx.user).await?;
    Ok(to.with(SuccessResponse::new(res)))
}

pub async fn get(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<()>,
    input: Query<AuthNPKInput>,
) -> Result<PackObject<SuccessResponse<AuthNOutput>>, HTTPError> {
    input.validate()?;

    ctx.set_kvs(vec![
        ("action", "get_authn".into()),
        ("idp", input.idp.clone().into()),
        ("aud", input.aud.clone().into()),
        ("sub", input.sub.clone().into()),
        ("uid", ctx.user.to_string().into()),
    ])
    .await;

    let mut doc = db::AuthN::with_pk(input.idp.clone(), input.aud.clone(), input.sub.clone());
    let fields = input
        .fields
        .clone()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.to_string())
        .collect();
    doc.get_one(&app.scylla, fields).await?;
    Ok(to.with(SuccessResponse::new(AuthNOutput::from(doc, &to))))
}
