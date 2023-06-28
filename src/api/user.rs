use axum::{
    extract::{Query, State},
    Extension,
};
use isolang::Language;
use serde::{Deserialize, Serialize};
use std::{convert::From, sync::Arc};
use validator::Validate;

use crate::db;

use axum_web::context::{unix_ms, ReqContext};
use axum_web::erring::{HTTPError, SuccessResponse};
use axum_web::object::PackObject;
use scylla_orm::ColumnsMap;

use crate::api::{group::GroupOutput, AppState, Pagination, QueryIdCn, UpdateSpecialFieldInput};

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct CreateUserInput {
    #[validate(length(min = 3, max = 24))]
    pub name: String,
    pub locale: PackObject<Language>,
    #[validate(url)]
    pub picture: Option<String>,
    pub gid: Option<PackObject<xid::Id>>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct UserOutput {
    pub id: PackObject<xid::Id>,
    pub cn: String,
    pub gid: PackObject<xid::Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rating: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<PackObject<Language>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<PackObject<Vec<u8>>>,
}

impl UserOutput {
    pub fn from<T>(val: db::User, to: &PackObject<T>) -> Self {
        let mut rt = Self {
            id: to.with(val.id),
            cn: val.cn,
            gid: to.with(val.gid),
            ..Default::default()
        };

        for v in val._fields {
            match v.as_str() {
                "status" => rt.status = Some(val.status),
                "rating" => rt.rating = Some(val.rating),
                "kind" => rt.kind = Some(val.kind),
                "created_at" => rt.created_at = Some(val.created_at),
                "updated_at" => rt.updated_at = Some(val.updated_at),
                "email" => rt.email = Some(val.email.to_owned()),
                "phone" => rt.phone = Some(val.phone.to_owned()),
                "name" => rt.name = Some(val.name.to_owned()),
                "birthdate" => rt.birthdate = Some(val.birthdate.to_owned()),
                "locale" => rt.locale = Some(to.with(val.locale)),
                "picture" => rt.picture = Some(val.picture.to_owned()),
                "address" => rt.address = Some(val.address.to_owned()),
                "website" => rt.website = Some(val.website.to_owned()),
                "bio" => rt.bio = Some(to.with(val.bio.to_owned())),
                _ => {}
            }
        }

        rt
    }
}

pub async fn create(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<CreateUserInput>,
) -> Result<PackObject<SuccessResponse<UserOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let id = xid::new();
    let mut doc = db::User {
        id,
        gid: input.gid.map_or(id, |id| id.unwrap()),
        name: input.name,
        locale: input.locale.unwrap(),
        picture: input.picture.unwrap_or_default(),
        ..Default::default()
    };

    if doc.gid != doc.id {
        let mut group = db::Group::with_pk(doc.gid);
        group
            .get_one(&app.scylla, vec!["status".to_string(), "kind".to_string()])
            .await?;
        if group.status < 0 {
            return Err(HTTPError::new(
                400,
                format!("group {} is not available", doc.gid),
            ));
        }
        doc.kind = group.kind;
    }

    let ok = doc.save(&app.scylla).await?;
    if doc.id == doc.gid {
        let mut group = db::Group {
            id: doc.id,
            cn: doc.cn.clone(),
            uid: doc.id,
            name: doc.name.clone(),
            logo: doc.picture.clone(),
            ..Default::default()
        };
        let res = group.save(&app.scylla).await;
        if res.is_err() {
            log::error!(target: "api",
                action = "create_user",
                gid = doc.id.to_string(),
                error = res.err().unwrap().to_string().as_str();
                "Create group for user {} failed", doc.id.to_string(),
            );
        }
    }

    ctx.set_kvs(vec![
        ("action", "create_user".into()),
        ("id", doc.id.to_string().into()),
        ("cn", doc.cn.clone().into()),
        ("gid", doc.gid.to_string().into()),
        ("created", ok.into()),
    ])
    .await;
    Ok(to.with(SuccessResponse::new(UserOutput::from(doc, &to))))
}

pub async fn get(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<()>,
    input: Query<QueryIdCn>,
) -> Result<PackObject<SuccessResponse<UserOutput>>, HTTPError> {
    input.validate()?;
    let id = if input.id.is_some() {
        input.id.as_ref().unwrap().to_owned().unwrap()
    } else {
        if input.cn.is_none() {
            return Err(HTTPError::new(400, "id or cn is required".into()));
        }

        let mut index = db::UserIndex::with_pk(input.cn.as_ref().unwrap().to_owned());
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

    let mut doc = db::User::with_pk(id);
    let fields = input
        .fields
        .clone()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.to_string())
        .collect();
    doc.get_one(&app.scylla, fields).await?;
    Ok(to.with(SuccessResponse::new(UserOutput::from(doc, &to))))
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserInput {
    pub id: PackObject<xid::Id>,
    pub updated_at: i64,
    #[validate(length(min = 3, max = 24))]
    pub name: Option<String>,
    pub birthdate: Option<String>,
    pub locale: Option<PackObject<Language>>,
    #[validate(url)]
    pub picture: Option<String>,
    #[validate(length(min = 2, max = 128))]
    pub address: Option<String>,
    #[validate(url)]
    pub website: Option<String>,
    pub bio: Option<PackObject<Vec<u8>>>,
}

impl UpdateUserInput {
    fn into(self) -> anyhow::Result<ColumnsMap> {
        let mut cols = ColumnsMap::new();
        if let Some(name) = self.name {
            cols.set_as("name", &name);
        }
        if let Some(birthdate) = self.birthdate {
            cols.set_as("birthdate", &birthdate);
        }
        if let Some(locale) = self.locale {
            cols.set_as("locale", &locale.unwrap());
        }
        if let Some(picture) = self.picture {
            cols.set_as("picture", &picture);
        }
        if let Some(address) = self.address {
            cols.set_as("address", &address);
        }
        if let Some(website) = self.website {
            cols.set_as("website", &website);
        }
        if let Some(bio) = self.bio {
            let bio = bio.unwrap();
            if bio.len() > 1024 {
                return Err(HTTPError::new(400, "Bio too long".to_string()).into());
            }
            cols.set_as("bio", &bio);
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
    to: PackObject<UpdateUserInput>,
) -> Result<PackObject<SuccessResponse<UserOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let id = *input.id.to_owned();
    let mut doc = db::User::with_pk(id);
    let updated_at = input.updated_at;
    let cols = input.into()?;
    ctx.set_kvs(vec![
        ("action", "update_user".into()),
        ("id", doc.id.to_string().into()),
    ])
    .await;

    let ok = doc.update(&app.scylla, cols, updated_at).await?;
    ctx.set("updated", ok.into()).await;

    doc._fields = vec!["updated_at".to_string()]; // only return `updated_at` field.
    Ok(to.with(SuccessResponse::new(UserOutput::from(doc, &to))))
}

pub async fn update_status(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<UpdateSpecialFieldInput>,
) -> Result<PackObject<SuccessResponse<UserOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;
    if input.status.is_none() {
        return Err(HTTPError::new(400, "status is required".into()));
    }

    let id = *input.id.to_owned();
    let status = input.status.unwrap();
    let mut doc = db::User::with_pk(id);
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
    Ok(to.with(SuccessResponse::new(UserOutput::from(doc, &to))))
}

pub async fn update_rating(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<UpdateSpecialFieldInput>,
) -> Result<PackObject<SuccessResponse<UserOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;
    if input.rating.is_none() {
        return Err(HTTPError::new(400, "rating is required".into()));
    }

    let id = *input.id.to_owned();
    let rating = input.rating.unwrap();
    let mut doc = db::User::with_pk(id);
    ctx.set_kvs(vec![
        ("action", "update_rating".into()),
        ("id", doc.id.to_string().into()),
        ("rating", rating.into()),
    ])
    .await;

    let ok = doc
        .update_rating(&app.scylla, rating, input.updated_at)
        .await?;

    ctx.set("updated", ok.into()).await;
    doc._fields = vec!["updated_at".to_string(), "rating".to_string()];
    Ok(to.with(SuccessResponse::new(UserOutput::from(doc, &to))))
}

pub async fn update_kind(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<UpdateSpecialFieldInput>,
) -> Result<PackObject<SuccessResponse<UserOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;
    if input.kind.is_none() {
        return Err(HTTPError::new(400, "kind is required".into()));
    }

    let id = *input.id.to_owned();
    let kind = input.kind.unwrap();
    let mut doc = db::User::with_pk(id);
    ctx.set_kvs(vec![
        ("action", "update_kind".into()),
        ("id", doc.id.to_string().into()),
        ("kind", kind.into()),
    ])
    .await;

    let ok = doc.update_kind(&app.scylla, kind, input.updated_at).await?;

    ctx.set("updated", ok.into()).await;
    doc._fields = vec!["updated_at".to_string(), "kind".to_string()];
    Ok(to.with(SuccessResponse::new(UserOutput::from(doc, &to))))
}

pub async fn update_email(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<UpdateSpecialFieldInput>,
) -> Result<PackObject<SuccessResponse<UserOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;
    if input.email.is_none() {
        return Err(HTTPError::new(400, "email is required".into()));
    }

    let id = *input.id.to_owned();
    let email = input.email.unwrap();
    let mut doc = db::User::with_pk(id);
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
    Ok(to.with(SuccessResponse::new(UserOutput::from(doc, &to))))
}

pub async fn update_phone(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<UpdateSpecialFieldInput>,
) -> Result<PackObject<SuccessResponse<UserOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;
    if input.phone.is_none() {
        return Err(HTTPError::new(400, "phone is required".into()));
    }

    let id = *input.id.to_owned();
    let phone = input.phone.unwrap();
    let mut doc = db::User::with_pk(id);
    ctx.set_kvs(vec![
        ("action", "update_phone".into()),
        ("id", doc.id.to_string().into()),
        ("phone", phone.clone().into()),
    ])
    .await;

    let ok = doc
        .update_phone(&app.scylla, phone, input.updated_at)
        .await?;

    ctx.set("updated", ok.into()).await;
    doc._fields = vec!["updated_at".to_string(), "phone".to_string()];
    Ok(to.with(SuccessResponse::new(UserOutput::from(doc, &to))))
}

pub async fn list_groups(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<Pagination>,
) -> Result<PackObject<SuccessResponse<Vec<GroupOutput>>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let page_size = input.page_size.unwrap_or(10);
    ctx.set_kvs(vec![("action", "list_users".into())]).await;

    let fields = input.fields.unwrap_or_default();
    let page_token = input.page_token.map(|s| s.unwrap());
    let res = db::Member::list_groups(
        &app.scylla,
        ctx.user,
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
            .map(|r| GroupOutput::from(r.to_owned(), &to))
            .collect(),
    }))
}
