use axum::{
    extract::{Query, State},
    Extension,
};

use serde::{Deserialize, Serialize};
use std::{convert::From, sync::Arc};
use validator::Validate;

use crate::db;

use axum_web::context::ReqContext;
use axum_web::erring::{HTTPError, SuccessResponse};
use axum_web::object::PackObject;


use crate::api::{user::UserOutput, AppState, QueryGidUid};

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct MemberInput {
    pub gid: PackObject<xid::Id>,
    pub uid: PackObject<xid::Id>,
    #[validate(range(min = -2, max = 2))]
    pub role: Option<i8>,
    #[validate(range(min = -1, max = 2))]
    pub priority: Option<i8>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct MemberOutput {
    pub gid: PackObject<xid::Id>,
    pub uid: PackObject<xid::Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _user: Option<UserOutput>,
}

impl MemberOutput {
    pub fn from<T>(val: db::Member, to: &PackObject<T>) -> Self {
        let mut rt = Self {
            gid: to.with(val.gid),
            uid: to.with(val.uid),
            ..Default::default()
        };

        for v in val._fields {
            match v.as_str() {
                "role" => rt.role = Some(val.role),
                "created_at" => rt.created_at = Some(val.created_at),
                "updated_at" => rt.updated_at = Some(val.updated_at),
                _ => {}
            }
        }

        rt
    }
}

pub async fn create(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<MemberInput>,
) -> Result<PackObject<SuccessResponse<MemberOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let gid = *input.gid.to_owned();
    let role = input.role.unwrap_or(0);
    let mut member = db::Member::with_pk(gid, ctx.user);
    member
        .get_one(&app.scylla, vec!["role".to_string()])
        .await?;
    if member.role < 1 {
        return Err(HTTPError::new(
            403,
            format!("Operator {} has no permision on group {}", ctx.user, gid),
        ));
    }
    if role > member.role {
        return Err(HTTPError::new(400, format!("Invalid role {}", role)));
    }

    let uid = *input.uid.to_owned();
    let mut user = db::User::with_pk(uid);
    user.get_one(&app.scylla, vec!["status".to_string()])
        .await?;
    if user.status < 0 {
        return Err(HTTPError::new(
            400,
            format!("User {} is not available", uid),
        ));
    }

    let mut group = db::Group::with_pk(gid);
    group
        .get_one(&app.scylla, vec!["status".to_string()])
        .await?;
    if group.status < 0 {
        return Err(HTTPError::new(
            400,
            format!("Group {} is not available", gid),
        ));
    }

    let mut doc = db::Member {
        gid,
        uid,
        role,
        ..Default::default()
    };

    let ok = doc.save(&app.scylla).await?;
    ctx.set_kvs(vec![
        ("action", "create_member".into()),
        ("gid", doc.gid.to_string().into()),
        ("uid", doc.uid.to_string().into()),
        ("created", ok.into()),
    ])
    .await;
    Ok(to.with(SuccessResponse::new(MemberOutput::from(doc, &to))))
}

pub async fn update_role(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<MemberInput>,
) -> Result<PackObject<SuccessResponse<MemberOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;
    if input.role.is_none() {
        return Err(HTTPError::new(400, "role is required".into()));
    }
    if input.updated_at.is_none() {
        return Err(HTTPError::new(400, "updated_at is required".into()));
    }

    let gid = *input.gid.to_owned();
    let uid = *input.uid.to_owned();
    let role = input.role.unwrap();
    let updated_at = input.updated_at.unwrap();

    let mut doc = db::Member::with_pk(gid, uid);
    ctx.set_kvs(vec![
        ("action", "update_role".into()),
        ("gid", doc.gid.to_string().into()),
        ("uid", doc.uid.to_string().into()),
        ("role", role.into()),
    ])
    .await;

    let ok = doc.update_role(&app.scylla, role, updated_at).await?;

    ctx.set("updated", ok.into()).await;
    doc._fields = vec!["updated_at".to_string(), "role".to_string()];
    Ok(to.with(SuccessResponse::new(MemberOutput::from(doc, &to))))
}

pub async fn update_priority(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<MemberInput>,
) -> Result<PackObject<SuccessResponse<MemberOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;
    if input.priority.is_none() {
        return Err(HTTPError::new(400, "priority is required".into()));
    }
    if input.updated_at.is_none() {
        return Err(HTTPError::new(400, "updated_at is required".into()));
    }

    let gid = *input.gid.to_owned();
    let uid = *input.uid.to_owned();
    if uid != ctx.user {
        return Err(HTTPError::new(400, format!("uid should be {}", ctx.user)));
    }

    let priority = input.priority.unwrap();
    let updated_at = input.updated_at.unwrap();

    let mut doc = db::Member::with_pk(gid, uid);
    ctx.set_kvs(vec![
        ("action", "update_priority".into()),
        ("gid", doc.gid.to_string().into()),
        ("uid", doc.uid.to_string().into()),
        ("priority", priority.into()),
    ])
    .await;

    let ok = doc
        .update_priority(&app.scylla, priority, updated_at)
        .await?;

    ctx.set("updated", ok.into()).await;
    doc._fields = vec!["updated_at".to_string(), "priority".to_string()];
    Ok(to.with(SuccessResponse::new(MemberOutput::from(doc, &to))))
}

pub async fn delete(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<()>,
    input: Query<QueryGidUid>,
) -> Result<PackObject<SuccessResponse<bool>>, HTTPError> {
    input.validate()?;

    let gid = input.gid.as_ref().to_owned();
    let uid = input.uid.as_ref().to_owned();

    ctx.set_kvs(vec![
        ("action", "delete_member".into()),
        ("gid", gid.to_string().into()),
        ("uid", uid.to_string().into()),
    ])
    .await;

    let mut member = db::Member::with_pk(gid, ctx.user);
    member
        .get_one(&app.scylla, vec!["role".to_string()])
        .await?;
    if ctx.user != uid && member.role < 1 {
        return Err(HTTPError::new(
            403,
            format!("Operator {} has no permision on group {}", ctx.user, gid),
        ));
    }

    let mut doc = db::Member::with_pk(gid, uid);
    let res = doc.delete(&app.scylla, input.updated_at).await?;
    Ok(to.with(SuccessResponse::new(res)))
}
