use axum::{
    extract::{Query, State},
    headers::{
        authorization::{Bearer, Credentials},
    },
    http::HeaderMap,
    Extension,
};
use serde::{Deserialize, Serialize};
use std::{convert::From, str::FromStr, sync::Arc};
use validator::Validate;

use axum_web::context::{unix_ms, ReqContext};
use axum_web::erring::{HTTPError, SuccessResponse};
use axum_web::object::PackObject;

use crate::api::{AppState, QuerySid};
use crate::crypto;
use crate::db;

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct SessionInput {
    pub session: String,
    pub ip: Option<String>,
    pub aid: Option<PackObject<xid::Id>>,
    #[validate(range(min = 1, max = 31536000))]
    pub expires_in: Option<i32>, // seconds, default to 3600, max to 365 days
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SessionVerifyOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<PackObject<xid::Id>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<PackObject<uuid::Uuid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i32>,
}

pub async fn min_verify(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<SessionInput>,
) -> Result<PackObject<SuccessResponse<SessionVerifyOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let (sid, uid, oid) = app
        .session
        .from(&input.session)
        .map_err(|e| HTTPError::new(401, format!("Invalid session, {}", e)))?;

    let oid_str = oid.map_or_else(|| "".to_string(), |v| v.to_string());
    ctx.set_kvs(vec![
        ("action", "verify".into()),
        ("sid", sid.to_string().into()),
        ("uid", uid.to_string().into()),
        ("oid", oid_str.into()),
    ])
    .await;
    let mut doc = db::Session::with_pk(sid);
    doc.get_one(&app.scylla, vec!["uid".to_string()])
        .await
        .map_err(|e| HTTPError::new(401, format!("Invalid session, {}", e)))?;

    if doc.uid != uid {
        return Err(HTTPError::new(
            500,
            format!(
                "Invalid session, uid not match, expected {}, got {}",
                doc.uid, uid
            ),
        ));
    }

    let mut output = SessionVerifyOutput {
        uid: None,
        oid: None,
        access_token: None,
        expires_in: None,
    };

    if oid.is_some() {
        // oid is not None, means it's a session from app
        output.oid = Some(to.with(oid.unwrap()));
    } else {
        output.uid = Some(to.with(uid));
    }
    Ok(to.with(SuccessResponse::new(output)))
}

pub async fn verify(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<SessionInput>,
) -> Result<PackObject<SuccessResponse<SessionVerifyOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let (sid, uid, oid) = app
        .session
        .from(&input.session)
        .map_err(|e| HTTPError::new(401, format!("Invalid session, {}", e)))?;

    let oid_str = oid.map_or_else(|| "".to_string(), |v| v.to_string());
    ctx.set_kvs(vec![
        ("action", "verify".into()),
        ("sid", sid.to_string().into()),
        ("uid", uid.to_string().into()),
        ("oid", oid_str.into()),
    ])
    .await;

    let mut doc = db::Session::with_pk(sid);
    doc.get_one(&app.scylla, vec!["uid".to_string(), "ip".to_string()])
        .await
        .map_err(|e| HTTPError::new(401, format!("Invalid session, {}", e)))?;

    if doc.uid != uid {
        return Err(HTTPError::new(
            500,
            format!(
                "Invalid session, uid not match, expected {}, got {}",
                doc.uid, uid
            ),
        ));
    }

    if let Some(ip) = input.ip {
        if ip != doc.ip {
            ctx.set("ip", ip.clone().into()).await;
            let _ = doc.update_ip(&app.scylla, ip).await;
        }
    }

    let mut user = db::User::with_pk(uid);
    user.get_one(&app.scylla, vec!["status".to_string()])
        .await
        .map_err(|e| HTTPError::new(401, format!("Invalid user, {}", e)))?;
    if user.status < 0 {
        return Err(HTTPError::new(
            403,
            format!("{} user, id {}", user.status_name(), user.id),
        ));
    }
    let mut output = SessionVerifyOutput {
        uid: None,
        oid: None,
        access_token: None,
        expires_in: None,
    };

    if oid.is_some() {
        // oid is not None, means it's a session from app
        output.oid = Some(to.with(oid.unwrap()));
    } else {
        output.uid = Some(to.with(uid));
    }
    Ok(to.with(SuccessResponse::new(output)))
}

pub async fn renew_token(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<SessionInput>,
) -> Result<PackObject<SuccessResponse<SessionVerifyOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    if input.aid.is_none() {
        return Err(HTTPError::new(
            400,
            "Invalid input, aid is none".to_string(),
        ));
    }

    let (sid, uid, oid) = app
        .session
        .from(&input.session)
        .map_err(|e| HTTPError::new(401, format!("Invalid session, {}", e)))?;

    let aid = input.aid.unwrap().unwrap();
    let jarvis = xid::Id::from_str(db::USER_JARVIS).unwrap();
    let mut gid = jarvis;
    if aid != jarvis {
        let mut app_user = db::User::with_pk(aid);
        app_user
            .get_one(
                &app.scylla,
                vec!["gid".to_string(), "status".to_string(), "kind".to_string()],
            )
            .await
            .map_err(|_| HTTPError::new(403, format!("Invalid app {}", aid)))?;
        if app_user.status < 0 {
            return Err(HTTPError::new(
                403,
                format!("{} app {}", app_user.status_name(), app_user.id),
            ));
        }
        if app_user.kind != -1 {
            return Err(HTTPError::new(
                403,
                format!("Invalid app {}, must be robot user", app_user.id),
            ));
        }
        if app_user.gid != jarvis {
            if oid.is_none() {
                return Err(HTTPError::new(
                    403,
                    "Invalid session, oid is none".to_string(),
                ));
            }
            gid = app_user.gid; // third party app
        }
    }

    let oid = oid.unwrap_or_else(|| app.mac_id.uuid(&gid, &uid));
    ctx.set_kvs(vec![
        ("action", "renew_token".into()),
        ("sid", sid.to_string().into()),
        ("uid", uid.to_string().into()),
        ("oid", oid.to_string().into()),
        ("aid", aid.to_string().into()),
    ])
    .await;

    let mut sess = db::Session::with_pk(sid);
    sess.get_one(
        &app.scylla,
        vec![
            "uid".to_string(),
            "ip".to_string(),
            "aid".to_string(),
            "oid".to_string(),
            "created_at".to_string(),
            "ttl".to_string(),
        ],
    )
    .await
    .map_err(|e| HTTPError::new(401, format!("Invalid session, {}", e)))?;

    if sess.uid != uid {
        return Err(HTTPError::new(
            500,
            format!(
                "Invalid session, uid not match, expected {}, got {}",
                sess.uid, uid
            ),
        ));
    }
    if sess.oid != oid.to_string() {
        return Err(HTTPError::new(
            500,
            format!(
                "Invalid session, oid not match, expected {}, got {}",
                sess.oid, oid
            ),
        ));
    }
    if sess.aid != aid.to_string() {
        return Err(HTTPError::new(
            500,
            format!(
                "Invalid session, aid not match, expected {}, got {}",
                sess.aid, aid
            ),
        ));
    }

    if let Some(ip) = input.ip {
        if ip != sess.ip {
            ctx.set("ip", ip.clone().into()).await;
            let _ = sess.update_ip(&app.scylla, ip).await;
        }
    }

    if gid != jarvis {
        let mut authz = db::AuthZ::with_pk(oid, aid);
        authz
            .get_one(
                &app.scylla,
                vec!["uid".to_string(), "expire_at".to_string()],
            )
            .await
            .map_err(|e| HTTPError::new(401, format!("Invalid authorization, {}", e)))?;
        if authz.uid != uid {
            return Err(HTTPError::new(
                500,
                format!(
                    "Invalid authorization, uid not match, expected {}, got {}",
                    authz.uid, uid
                ),
            ));
        }
    }

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
    .map_err(|e| HTTPError::new(401, format!("Invalid user, {}", e)))?;
    if user.status < 0 {
        return Err(HTTPError::new(
            403,
            format!("{} user, id {}", user.status_name(), user.id),
        ));
    }

    let now = (unix_ms() / 1000) as i64;
    let expires_in = input.expires_in.unwrap_or(3600);
    let exp = now + expires_in as i64;

    let token = crypto::Token {
        user: oid,
        app: aid,
        exp,
        iat: now,
        sid,
        uid: user.id,
        status: user.status,
        rating: user.rating,
        kind: user.kind,
        ..Default::default()
    };

    let token = app
        .cwt
        .sign(token)
        .map_err(|e| HTTPError::new(500, format!("Failed to sign token, {}", e)))?;

    if sess.created_at + 1000 * 3600 * 24 < now * 1000 {
        match sess.renew(&app.scylla).await {
            Ok(rt) => {
                ctx.set("renew_session", rt.into()).await;
            }
            Err(e) => {
                log::error!(target: "api",
                    action = "renew_session",
                    sid = sess.id.to_string(),
                    error = e.to_string().as_str();
                    "Failed to renew session",
                );
            }
        }
    }

    Ok(to.with(SuccessResponse::new(SessionVerifyOutput {
        uid: None,
        oid: Some(to.with(oid)),
        access_token: Some(crypto::base64url_encode(&token)),
        expires_in: Some(expires_in),
    })))
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SessionOutput {
    pub id: PackObject<xid::Id>,
    pub uid: PackObject<xid::Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_desc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

impl SessionOutput {
    pub fn from<T>(val: db::Session, to: &PackObject<T>) -> Self {
        let mut rt = Self {
            id: to.with(val.id),
            uid: to.with(val.uid),
            ..Default::default()
        };

        for v in val._fields {
            match v.as_str() {
                "ip" => rt.ip = Some(val.ip.to_owned()),
                "created_at" => rt.created_at = Some(val.created_at),
                "updated_at" => rt.updated_at = Some(val.updated_at),
                "device_id" => rt.device_id = Some(val.device_id.to_owned()),
                "device_desc" => rt.device_desc = Some(val.device_desc.to_owned()),
                "idp" => rt.idp = Some(val.idp.to_owned()),
                "aid" => rt.aid = Some(val.aid.to_owned()),
                "oid" => rt.oid = Some(val.oid.to_owned()),
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
) -> Result<PackObject<SuccessResponse<Vec<SessionOutput>>>, HTTPError> {
    ctx.set_kvs(vec![
        ("action", "list_sessions".into()),
        ("uid", ctx.user.to_string().into()),
    ])
    .await;
    let res = db::Session::list_by_uid(&app.scylla, ctx.user, vec![]).await?;
    Ok(to.with(SuccessResponse {
        total_size: None,
        next_page_token: None,
        result: res
            .iter()
            .map(|r| SessionOutput::from(r.to_owned(), &to))
            .collect(),
    }))
}

pub async fn delete(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<()>,
    input: Query<QuerySid>,
) -> Result<PackObject<SuccessResponse<bool>>, HTTPError> {
    input.validate()?;

    let sid = input.sid.as_ref().to_owned();
    ctx.set_kvs(vec![
        ("action", "delete_session".into()),
        ("sid", sid.to_string().into()),
        ("uid", ctx.user.to_string().into()),
    ])
    .await;

    let mut doc = db::Session::with_pk(sid);
    let res = doc.delete(&app.scylla, ctx.user).await?;
    Ok(to.with(SuccessResponse::new(res)))
}

pub async fn get(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<()>,
    input: Query<QuerySid>,
) -> Result<PackObject<SuccessResponse<SessionOutput>>, HTTPError> {
    input.validate()?;

    let sid = input.sid.as_ref().to_owned();
    ctx.set_kvs(vec![
        ("action", "get_session".into()),
        ("sid", sid.to_string().into()),
        ("uid", ctx.user.to_string().into()),
    ])
    .await;

    let mut doc = db::Session::with_pk(sid);
    let fields = input
        .fields
        .clone()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.to_string())
        .collect();
    doc.get_one(&app.scylla, fields).await?;
    Ok(to.with(SuccessResponse::new(SessionOutput::from(doc, &to))))
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct TokenVerifyOutput {
    pub uid: PackObject<xid::Id>,
    pub aid: PackObject<xid::Id>,
    pub oid: PackObject<uuid::Uuid>,
    pub scope: String,
    pub status: i8,
    pub rating: i8,
    pub kind: i8,
}

pub async fn min_verify_token(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<()>,
    headers: HeaderMap,
) -> Result<PackObject<SuccessResponse<TokenVerifyOutput>>, HTTPError> {
    let token = headers
        .get("Authorization")
        .ok_or_else(|| HTTPError::new(401, "Missing Authorization header".to_string()))?;

    let token = Bearer::decode(token).ok_or_else(|| {
        HTTPError::new(
            401,
            "Expected Bearer token on authorization header".to_string(),
        )
    })?;

    let token = crypto::base64url_decode(token.token())
        .map_err(|_| HTTPError::new(401, "Invalid token".to_string()))?;

    let token = app
        .cwt
        .verify(&token)
        .map_err(|_| HTTPError::new(401, "Invalid token".to_string()))?;

    ctx.set_kvs(vec![
        ("action", "min_verify_token".into()),
        ("uid", token.uid.to_string().into()),
        ("oid", token.user.to_string().into()),
    ])
    .await;

    if let Err(err) = token.validate() {
        return Err(HTTPError::new(401, err.to_string()));
    }

    let mut sess = db::Session::with_pk(token.sid);
    sess.get_one(&app.scylla, vec!["ttl".to_string()])
        .await
        .map_err(|_| HTTPError::new(401, format!("Invalid session, {}", token.sid)))?;

    Ok(to.with(SuccessResponse::new(TokenVerifyOutput {
        uid: to.with(token.uid),
        aid: to.with(token.app),
        oid: to.with(token.user),
        scope: token.scope,
        status: token.status,
        rating: token.rating,
        kind: token.kind,
    })))
}

pub async fn verify_token(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<()>,
    headers: HeaderMap,
) -> Result<PackObject<SuccessResponse<TokenVerifyOutput>>, HTTPError> {
    let token = headers
        .get("Authorization")
        .ok_or_else(|| HTTPError::new(401, "Missing Authorization header".to_string()))?;

    let token = Bearer::decode(token).ok_or_else(|| {
        HTTPError::new(
            401,
            "Expected Bearer token on authorization header".to_string(),
        )
    })?;

    let token = crypto::base64url_decode(token.token())
        .map_err(|_| HTTPError::new(401, "Invalid token".to_string()))?;

    let token = app
        .cwt
        .verify(&token)
        .map_err(|_| HTTPError::new(401, "Invalid token".to_string()))?;

    ctx.set_kvs(vec![
        ("action", "min_verify_token".into()),
        ("uid", token.uid.to_string().into()),
        ("oid", token.user.to_string().into()),
    ])
    .await;

    if let Err(err) = token.validate() {
        return Err(HTTPError::new(401, err.to_string()));
    }

    let mut sess = db::Session::with_pk(token.sid);
    sess.get_one(&app.scylla, vec!["ttl".to_string()])
        .await
        .map_err(|_| HTTPError::new(401, format!("Invalid session, {}", token.sid)))?;

    let jarvis = xid::Id::from_str(db::USER_JARVIS).unwrap();
    if token.app != jarvis {
        let mut app_user = db::User::with_pk(token.app);
        app_user
            .get_one(&app.scylla, vec!["status".to_string()])
            .await
            .map_err(|_| HTTPError::new(403, format!("Invalid app {}", token.app)))?;
        if app_user.status < 0 {
            return Err(HTTPError::new(
                403,
                format!("{} app {}", app_user.status_name(), app_user.id),
            ));
        }
    }

    let mut user = db::User::with_pk(token.uid);
    user.get_one(
        &app.scylla,
        vec![
            "status".to_string(),
            "rating".to_string(),
            "kind".to_string(),
        ],
    )
    .await
    .map_err(|_| HTTPError::new(401, format!("Invalid user, {}", token.uid)))?;
    if user.status < 0 {
        return Err(HTTPError::new(
            403,
            format!("{} user, id {}", user.status_name(), user.id),
        ));
    }

    Ok(to.with(SuccessResponse::new(TokenVerifyOutput {
        uid: to.with(token.uid),
        aid: to.with(token.app),
        oid: to.with(token.user),
        scope: token.scope,
        status: user.status,
        rating: user.rating,
        kind: user.kind,
    })))
}
