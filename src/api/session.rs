use axum::{
    extract::{Query, State},
    headers::{
        authorization::{Bearer, Credentials},
        HeaderValue,
    },
    http::{HeaderMap, StatusCode},
    response::Response,
    Extension,
};
use cookie::Cookie;
use serde::{Deserialize, Serialize};
use std::{convert::From, str::FromStr, sync::Arc};
use validator::Validate;

use axum_web::context::{unix_ms, ReqContext};
use axum_web::erring::{HTTPError, SuccessResponse};
use axum_web::object::PackObject;

use crate::api::{get_fields, AppState, QuerySid};
use crate::crypto;
use crate::db;

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct SessionInput {
    pub session: String,
    pub aud: PackObject<xid::Id>,
    #[validate(range(min = 1, max = 31536000))]
    pub expires_in: Option<i32>, // seconds, default to 3600, max to 365 days
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SessionVerifyOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<PackObject<xid::Id>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<PackObject<uuid::Uuid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>, // TODO https://openid.net/specs/openid-connect-core-1_0.html
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

    let (sid, uid, sub) = app
        .session
        .from(&input.session)
        .map_err(|e| HTTPError::new(401, format!("Invalid session, {}", e)))?;

    let sub_str = sub.map_or_else(|| "".to_string(), |v| v.to_string());
    ctx.set_kvs(vec![
        ("action", "verify".into()),
        ("sid", sid.to_string().into()),
        ("uid", uid.to_string().into()),
        ("sub", sub_str.into()),
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

    let output = SessionVerifyOutput {
        uid: Some(to.with(uid)),
        sub: sub.map(|v| to.with(v)),
        access_token: None,
        id_token: None,
        expires_in: None,
    };

    Ok(to.with(SuccessResponse::new(output)))
}

pub async fn verify(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<SessionInput>,
) -> Result<PackObject<SuccessResponse<SessionVerifyOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let (sid, uid, sub) = app
        .session
        .from(&input.session)
        .map_err(|e| HTTPError::new(401, format!("Invalid session, {}", e)))?;

    let sub_str = sub.map_or_else(|| "".to_string(), |v| v.to_string());
    ctx.set_kvs(vec![
        ("action", "verify".into()),
        ("sid", sid.to_string().into()),
        ("uid", uid.to_string().into()),
        ("sub", sub_str.into()),
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

    let mut user = db::User::with_pk(uid);
    user.get_one(&app.scylla, vec!["status".to_string()])
        .await
        .map_err(|e| HTTPError::new(401, format!("Invalid user, {}", e)))?;
    if user.status < -1 {
        return Err(HTTPError::new(
            403,
            format!("{} user, id {}", user.status_name(), user.id),
        ));
    }

    let output = SessionVerifyOutput {
        uid: Some(to.with(uid)),
        sub: sub.map(|v| to.with(v)),
        access_token: None,
        id_token: None,
        expires_in: None,
    };
    Ok(to.with(SuccessResponse::new(output)))
}

pub async fn renew_token(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<SessionInput>,
) -> Result<PackObject<SuccessResponse<SessionVerifyOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let (sid, uid, sub) = app
        .session
        .from(&input.session)
        .map_err(|e| HTTPError::new(401, format!("Invalid session, {}", e)))?;

    let aud = input.aud.unwrap();
    let jarvis = xid::Id::from_str(db::USER_JARVIS).unwrap();
    let mut gid = jarvis;
    if aud != jarvis {
        let mut app_user = db::User::with_pk(aud);
        app_user
            .get_one(
                &app.scylla,
                vec!["gid".to_string(), "status".to_string(), "kind".to_string()],
            )
            .await
            .map_err(|_| HTTPError::new(403, format!("Invalid app {}", aud)))?;
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
            if sub.is_none() {
                return Err(HTTPError::new(
                    403,
                    "Invalid session, sub is none".to_string(),
                ));
            }
            gid = app_user.gid; // third party app
        }
    }

    let sub = sub.unwrap_or_else(|| app.mac_id.uuid(&gid, &uid));
    ctx.set_kvs(vec![
        ("action", "renew_token".into()),
        ("sid", sid.to_string().into()),
        ("uid", uid.to_string().into()),
        ("sub", sub.to_string().into()),
        ("aud", aud.to_string().into()),
    ])
    .await;

    let mut sess = db::Session::with_pk(sid);
    sess.get_one(
        &app.scylla,
        vec![
            "uid".to_string(),
            "aud".to_string(),
            "sub".to_string(),
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

    if gid != jarvis {
        if sess.sub != sub.to_string() {
            return Err(HTTPError::new(
                500,
                format!(
                    "Invalid session, sub not match, expected {}, got {}",
                    sess.sub, sub
                ),
            ));
        }
        if sess.aud != aud.to_string() {
            return Err(HTTPError::new(
                500,
                format!(
                    "Invalid session, aud not match, expected {}, got {}",
                    sess.aud, aud
                ),
            ));
        }

        let mut authz = db::AuthZ::with_pk(aud, sub);
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
            "birthdate".to_string(),
        ],
    )
    .await
    .map_err(|e| HTTPError::new(401, format!("Invalid user, {}", e)))?;
    if user.status < -1 {
        return Err(HTTPError::new(
            403,
            format!("{} user, id {}", user.status_name(), user.id),
        ));
    }

    let now = (unix_ms() / 1000) as i64;
    let expires_in = input.expires_in.unwrap_or(3600);
    let exp = now + expires_in as i64;

    let token = crypto::Token {
        sub,
        aud,
        exp,
        iat: now,
        sid,
        uid: user.id,
        status: user.status,
        rating: user.get_rating(),
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
        sub: Some(to.with(sub)),
        access_token: Some(crypto::base64url_encode(&token)),
        id_token: None,
        expires_in: Some(expires_in),
    })))
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SessionOutput {
    pub id: PackObject<xid::Id>,
    pub uid: PackObject<xid::Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_desc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
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
                "created_at" => rt.created_at = Some(val.created_at),
                "updated_at" => rt.updated_at = Some(val.updated_at),
                "ttl" => rt.ttl = Some(val.ttl),
                "device_id" => rt.device_id = Some(val.device_id.to_owned()),
                "device_desc" => rt.device_desc = Some(val.device_desc.to_owned()),
                "idp" => rt.idp = Some(val.idp.to_owned()),
                "aud" => rt.aud = Some(val.aud.to_owned()),
                "sub" => rt.sub = Some(val.sub.to_owned()),
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
    doc.get_one(&app.scylla, get_fields(input.fields.clone()))
        .await?;
    Ok(to.with(SuccessResponse::new(SessionOutput::from(doc, &to))))
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct TokenVerifyOutput {
    pub uid: PackObject<xid::Id>,
    pub aud: PackObject<xid::Id>,
    pub sub: PackObject<uuid::Uuid>,
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
        ("sub", token.sub.to_string().into()),
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
        aud: to.with(token.aud),
        sub: to.with(token.sub),
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
        ("sub", token.sub.to_string().into()),
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
    if token.aud != jarvis {
        let mut app_user = db::User::with_pk(token.aud);
        app_user
            .get_one(&app.scylla, vec!["status".to_string()])
            .await
            .map_err(|_| HTTPError::new(403, format!("Invalid app {}", token.aud)))?;
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
    if user.status < -1 {
        return Err(HTTPError::new(
            403,
            format!("{} user, id {}", user.status_name(), user.id),
        ));
    }

    Ok(to.with(SuccessResponse::new(TokenVerifyOutput {
        uid: to.with(token.uid),
        aud: to.with(token.aud),
        sub: to.with(token.sub),
        scope: token.scope,
        status: user.status,
        rating: user.rating,
        kind: user.kind,
    })))
}

pub async fn forward_auth(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let mut res_headers = HeaderMap::new();
    let deault_value = HeaderValue::from_static("");

    // add X-Real-Ip
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_for) = forwarded_for.to_str() {
            let real_ip = forwarded_for.split(',').next().unwrap_or_default().trim();
            if !real_ip.is_empty() {
                res_headers.insert(
                    "x-real-ip",
                    real_ip.parse().unwrap_or_else(|_| deault_value.clone()),
                );
            }
        }
    }

    // add X-Request-Id
    let mut request_id = headers
        .get("x-request-id")
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    if request_id.is_empty() {
        request_id = uuid::Uuid::new_v4().to_string();
    }
    res_headers.insert(
        "x-request-id",
        request_id.parse().unwrap_or_else(|_| deault_value.clone()),
    );

    let mut session = headers
        .get("x-session")
        .map_or_else(|| "", |v| v.to_str().unwrap_or_default())
        .to_string();
    let mut device_id = headers
        .get("x-device-id")
        .map_or_else(|| "", |v| v.to_str().unwrap_or_default())
        .to_string();
    if let Some(Ok(cookie_str)) = headers.get("cookie").map(|v| v.to_str()) {
        let sess_name = app.session_name_prefix.to_string() + "_SESS";
        let sess_id = app.session_name_prefix.to_string() + "_DID";
        for cookie in Cookie::split_parse_encoded(cookie_str).flatten() {
            match cookie.name() {
                name if sess_name == name => {
                    session = cookie.value().to_string();
                }
                name if sess_id == name => {
                    device_id = cookie.value().to_string();
                }
                _ => {}
            };
        }
    }

    // add X-Device-Id
    if !device_id.is_empty() {
        res_headers.insert(
            "x-device-id",
            device_id.parse().unwrap_or_else(|_| deault_value.clone()),
        );
    }

    // add:
    // X-Auth-User
    // X-Auth-User-Status
    // X-Auth-User-Rating
    // X-Auth-User-Kind
    // X-Auth-App
    // X-Auth-App-Scope
    if !session.is_empty() {
        if let Ok((sid, uid, _)) = app.session.from(&session) {
            let mut doc = db::Session::with_pk(sid);
            if doc
                .get_one(&app.scylla, vec!["uid".to_string()])
                .await
                .is_ok()
                && doc.uid == uid
            {
                res_headers.insert("x-auth-user", uid.to_string().parse().unwrap());

                if let Some(token) = headers.get("authorization") {
                    if let Some(token) = Bearer::decode(token) {
                        if let Ok(token) = crypto::base64url_decode(token.token()) {
                            if let Ok(token) = app.cwt.verify(&token) {
                                if token.validate().is_ok() && token.sid == sid {
                                    res_headers.insert(
                                        "x-auth-user-status",
                                        token.status.to_string().parse().unwrap(),
                                    );
                                    res_headers.insert(
                                        "x-auth-user-rating",
                                        token.rating.to_string().parse().unwrap(),
                                    );
                                    res_headers.insert(
                                        "x-auth-user-kind",
                                        token.kind.to_string().parse().unwrap(),
                                    );

                                    res_headers.insert(
                                        "x-auth-app",
                                        token.aud.to_string().parse().unwrap(),
                                    );
                                    res_headers
                                        .insert("x-auth-app-scope", token.scope.parse().unwrap());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut response = Response::default();
    *response.status_mut() = StatusCode::NO_CONTENT;
    *response.headers_mut() = res_headers;
    response
}
