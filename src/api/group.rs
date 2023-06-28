use axum::{
    extract::{Query, State},
    Extension,
};

use serde::{Deserialize, Serialize};
use std::{convert::From, sync::Arc};
use validator::Validate;

use crate::db;

use axum_web::context::{unix_ms, ReqContext};
use axum_web::erring::{HTTPError, SuccessResponse};
use axum_web::object::PackObject;
use scylla_orm::ColumnsMap;

use crate::api::{
    member::MemberOutput, user::UserOutput, AppState, Pagination, QueryIdCn,
    UpdateSpecialFieldInput,
};

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct CreateGroupInput {
    #[validate(length(min = 3, max = 24))]
    pub name: String,
    #[validate(url)]
    pub logo: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct GroupOutput {
    pub id: PackObject<xid::Id>,
    pub cn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<PackObject<xid::Id>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slogan: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<PackObject<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _role: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _priority: Option<i8>,
}

impl GroupOutput {
    pub fn from<T>(val: db::Group, to: &PackObject<T>) -> Self {
        let mut rt = Self {
            id: to.with(val.id),
            cn: val.cn,
            ..Default::default()
        };

        for v in val._fields {
            match v.as_str() {
                "uid" => rt.uid = Some(to.with(val.uid)),
                "status" => rt.status = Some(val.status),
                "kind" => rt.kind = Some(val.kind),
                "created_at" => rt.created_at = Some(val.created_at),
                "updated_at" => rt.updated_at = Some(val.updated_at),
                "email" => rt.email = Some(val.email.to_owned()),
                "legal_name" => rt.legal_name = Some(val.legal_name.to_owned()),
                "name" => rt.name = Some(val.name.to_owned()),
                "keywords" => rt.keywords = Some(val.keywords.to_owned()),
                "logo" => rt.logo = Some(val.logo.to_owned()),
                "slogan" => rt.slogan = Some(val.slogan.to_owned()),
                "address" => rt.address = Some(val.address.to_owned()),
                "website" => rt.website = Some(val.website.to_owned()),
                "description" => rt.description = Some(to.with(val.description.to_owned())),
                "_role" => rt._role = Some(val._role),
                "_priority" => rt._priority = Some(val._priority),
                _ => {}
            }
        }

        rt
    }
}

pub async fn create(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<CreateGroupInput>,
) -> Result<PackObject<SuccessResponse<GroupOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let mut doc = db::Group {
        id: xid::new(),
        uid: ctx.user,
        name: input.name,
        logo: input.logo.unwrap_or_default(),
        ..Default::default()
    };

    let ok = doc.save(&app.scylla).await?;
    ctx.set_kvs(vec![
        ("action", "create_group".into()),
        ("cn", doc.cn.clone().into()),
        ("id", doc.id.to_string().into()),
        ("created", ok.into()),
    ])
    .await;

    let mut member = db::Member {
        gid: doc.id,
        uid: doc.uid,
        role: 2,
        ..Default::default()
    };
    member.save(&app.scylla).await?;
    Ok(to.with(SuccessResponse::new(GroupOutput::from(doc, &to))))
}

pub async fn get(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<()>,
    input: Query<QueryIdCn>,
) -> Result<PackObject<SuccessResponse<GroupOutput>>, HTTPError> {
    input.validate()?;
    let id = if input.id.is_some() {
        input.id.as_ref().unwrap().to_owned().unwrap()
    } else {
        if input.cn.is_none() {
            return Err(HTTPError::new(400, "id or cn is required".into()));
        }

        let mut index = db::GroupIndex::with_pk(input.cn.as_ref().unwrap().to_owned());
        index.get_one(&app.scylla).await?;
        if index.expire_at < unix_ms() as i64 {
            return Err(HTTPError::new(404, format!("user {} not found", index.cn)));
        }

        index.id
    };

    ctx.set_kvs(vec![
        ("action", "get_user".into()),
        ("id", id.to_string().into()),
    ])
    .await;

    let mut doc = db::Group::with_pk(id);
    let fields = input
        .fields
        .clone()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.to_string())
        .collect();
    doc.get_one(&app.scylla, fields).await?;
    Ok(to.with(SuccessResponse::new(GroupOutput::from(doc, &to))))
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateGroupInput {
    pub id: PackObject<xid::Id>,
    pub updated_at: i64,
    #[validate(length(min = 3, max = 24))]
    pub name: Option<String>,
    #[validate(length(min = 0, max = 6))]
    pub keywords: Option<Vec<String>>,
    #[validate(url)]
    pub logo: Option<String>,
    #[validate(length(min = 10, max = 127))]
    pub slogan: Option<String>,
    #[validate(length(min = 3, max = 127))]
    pub address: Option<String>,
    #[validate(url)]
    pub website: Option<String>,
    pub description: Option<PackObject<Vec<u8>>>,
}

impl UpdateGroupInput {
    fn into(self) -> anyhow::Result<ColumnsMap> {
        let mut cols = ColumnsMap::new();
        if let Some(name) = self.name {
            cols.set_as("name", &name);
        }
        if let Some(keywords) = self.keywords {
            cols.set_as("keywords", &keywords);
        }
        if let Some(logo) = self.logo {
            cols.set_as("logo", &logo);
        }
        if let Some(slogan) = self.slogan {
            cols.set_as("slogan", &slogan);
        }
        if let Some(address) = self.address {
            cols.set_as("address", &address);
        }
        if let Some(website) = self.website {
            cols.set_as("website", &website);
        }
        if let Some(description) = self.description {
            let description = description.unwrap();
            if description.len() > 1024 {
                return Err(HTTPError::new(400, "Description too long".to_string()).into());
            }
            cols.set_as("description", &description);
        }

        if cols.is_empty() {
            return Err(HTTPError::new(400, "No fields to update".to_string()).into());
        }

        Ok(cols)
    }
}

pub async fn update(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<UpdateGroupInput>,
) -> Result<PackObject<SuccessResponse<GroupOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let id = *input.id.to_owned();
    let mut doc = db::Group::with_pk(id);
    let updated_at = input.updated_at;
    let cols = input.into()?;
    ctx.set_kvs(vec![
        ("action", "update_group".into()),
        ("id", doc.id.to_string().into()),
    ])
    .await;

    let ok = doc.update(&app.scylla, cols, updated_at).await?;
    ctx.set("updated", ok.into()).await;

    doc._fields = vec!["updated_at".to_string()]; // only return `updated_at` field.
    Ok(to.with(SuccessResponse::new(GroupOutput::from(doc, &to))))
}

pub async fn update_status(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<UpdateSpecialFieldInput>,
) -> Result<PackObject<SuccessResponse<GroupOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;
    if input.status.is_none() {
        return Err(HTTPError::new(400, "status is required".into()));
    }

    let id = *input.id.to_owned();
    let status = input.status.unwrap();
    let mut doc = db::Group::with_pk(id);
    ctx.set_kvs(vec![
        ("action", "update_status".into()),
        ("id", doc.id.to_string().into()),
        ("status", status.into()),
    ])
    .await;

    let ok = doc
        .update_status(&app.scylla, status, input.updated_at)
        .await?;

    ctx.set("updated", ok.into()).await;
    doc._fields = vec!["updated_at".to_string(), "status".to_string()];
    Ok(to.with(SuccessResponse::new(GroupOutput::from(doc, &to))))
}

pub async fn update_kind(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<UpdateSpecialFieldInput>,
) -> Result<PackObject<SuccessResponse<GroupOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;
    if input.kind.is_none() {
        return Err(HTTPError::new(400, "kind is required".into()));
    }

    let id = *input.id.to_owned();
    let kind = input.kind.unwrap();
    let mut doc = db::Group::with_pk(id);
    ctx.set_kvs(vec![
        ("action", "update_kind".into()),
        ("id", doc.id.to_string().into()),
        ("kind", kind.into()),
    ])
    .await;

    let ok = doc.update_kind(&app.scylla, kind, input.updated_at).await?;

    ctx.set("updated", ok.into()).await;
    doc._fields = vec!["updated_at".to_string(), "kind".to_string()];
    Ok(to.with(SuccessResponse::new(GroupOutput::from(doc, &to))))
}

pub async fn update_email(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<UpdateSpecialFieldInput>,
) -> Result<PackObject<SuccessResponse<GroupOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;
    if input.email.is_none() {
        return Err(HTTPError::new(400, "email is required".into()));
    }

    let id = *input.id.to_owned();
    let email = input.email.unwrap();
    let mut doc = db::Group::with_pk(id);
    ctx.set_kvs(vec![
        ("action", "update_email".into()),
        ("id", doc.id.to_string().into()),
        ("status", email.clone().into()),
    ])
    .await;

    let ok = doc
        .update_email(&app.scylla, email, input.updated_at)
        .await?;

    ctx.set("updated", ok.into()).await;
    doc._fields = vec!["updated_at".to_string(), "email".to_string()];
    Ok(to.with(SuccessResponse::new(GroupOutput::from(doc, &to))))
}

pub async fn list_users(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<Pagination>,
) -> Result<PackObject<SuccessResponse<Vec<UserOutput>>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    if input.gid.is_none() {
        return Err(HTTPError::new(400, "gid is required".into()));
    }
    let gid = *input.gid.unwrap();
    let page_size = input.page_size.unwrap_or(10);
    ctx.set_kvs(vec![("action", "list_users".into())]).await;

    let fields = input.fields.unwrap_or_default();
    let page_token = input.page_token.map(|s| s.unwrap());
    let res = db::User::list_group_users(
        &app.scylla,
        gid,
        fields,
        page_size,
        page_token,
        input.status,
    )
    .await?;
    let next_page_token = if res.len() >= page_size as usize {
        Some(res.last().unwrap().id.to_string())
    } else {
        None
    };

    Ok(to.with(SuccessResponse {
        total_size: None,
        next_page_token,
        result: res
            .iter()
            .map(|r| UserOutput::from(r.to_owned(), &to))
            .collect(),
    }))
}

pub async fn list_members(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<Pagination>,
) -> Result<PackObject<SuccessResponse<Vec<MemberOutput>>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    if input.gid.is_none() {
        return Err(HTTPError::new(400, "gid is required".into()));
    }
    let gid = *input.gid.unwrap();
    let page_size = input.page_size.unwrap_or(10);
    ctx.set_kvs(vec![("action", "list_users".into())]).await;

    let fields = input.fields.unwrap_or_default();
    let page_token = input.page_token.map(|s| s.unwrap());
    let res = db::Member::list_members(
        &app.scylla,
        gid,
        fields,
        page_size,
        page_token,
        input.status,
    )
    .await?;
    let next_page_token = if res.len() >= page_size as usize {
        Some(res.last().unwrap().uid.to_string())
    } else {
        None
    };

    Ok(to.with(SuccessResponse {
        total_size: None,
        next_page_token,
        result: res
            .iter()
            .map(|r| MemberOutput::from(r.to_owned(), &to))
            .collect(),
    }))
}
