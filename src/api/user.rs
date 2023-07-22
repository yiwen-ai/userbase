use axum::{
    extract::{Query, State},
    Extension,
};
use chrono::{Datelike, NaiveDate, NaiveDateTime};
use isolang::Language;
use serde::{Deserialize, Serialize};
use std::{convert::From, sync::Arc};
use validator::Validate;

use crate::db;

use axum_web::context::{unix_ms, ReqContext};
use axum_web::erring::{HTTPError, SuccessResponse};
use axum_web::object::PackObject;
use scylla_orm::ColumnsMap;

use crate::api::{
    get_fields, group::GroupOutput, token_from_xid, token_to_xid, AppState, BatchIdsInput,
    Pagination, QueryGid, QueryIdCn, UpdateSpecialFieldInput,
};

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct CreateUserInput {
    #[validate(length(min = 3, max = 24))]
    pub name: String,
    pub locale: PackObject<Language>,
    #[validate(url)]
    pub picture: Option<String>,
    pub birthdate: Option<String>,
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
                "birthdate" => {
                    rt.birthdate = if val.birthdate > 0 {
                        let birthdate =
                            NaiveDate::from_num_days_from_ce_opt(val.birthdate).unwrap_or_default();
                        Some(birthdate.format("%Y-%m-%d").to_string())
                    } else {
                        Some("".to_string())
                    };
                }
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
    to: PackObject<CreateUserInput>,
) -> Result<PackObject<SuccessResponse<UserOutput>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    let doc = internal_create(app, input).await?;
    Ok(to.with(SuccessResponse::new(UserOutput::from(doc, &to))))
}

pub async fn internal_create(
    app: Arc<AppState>,
    input: CreateUserInput,
) -> Result<db::User, HTTPError> {
    let id = xid::new();
    let mut doc = db::User {
        id,
        gid: input.gid.map_or(id, |id| id.unwrap()),
        name: input.name,
        locale: input.locale.unwrap(),
        picture: input.picture.unwrap_or_default(),
        ..Default::default()
    };

    if let Some(birthdate) = input.birthdate {
        let birthdate = NaiveDate::parse_from_str(&birthdate, "%Y-%m-%d")
            .map_err(|_| HTTPError::new(400, format!("invalid birthdate {}", &birthdate)))?;
        let nowdate = NaiveDateTime::from_timestamp_millis(unix_ms() as i64)
            .unwrap()
            .date();

        let year = birthdate.year();

        if year <= 1900 || year >= nowdate.year() {
            return Err(HTTPError::new(
                400,
                format!("invalid birthdate {}", &birthdate),
            ));
        }

        doc.birthdate = birthdate.num_days_from_ce();
    }

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

    let _ = doc.save(&app.scylla).await?;
    if doc.id == doc.gid {
        let mut group = db::Group {
            id: doc.id,
            cn: doc.cn.clone(),
            uid: doc.id,
            name: doc.name.clone(),
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

    Ok(doc)
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
    doc.get_one(&app.scylla, get_fields(input.fields.clone()))
        .await?;
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
    ctx.set_kvs(vec![("action", "list_user_groups".into())])
        .await;

    let fields = input.fields.unwrap_or_default();
    let mut usergroup = db::Group::with_pk(ctx.user);
    usergroup.get_one(&app.scylla, fields.clone()).await?;
    usergroup._role = 2i8;
    usergroup._priority = 2i8;
    usergroup._fields.push("_role".to_string());
    usergroup._fields.push("_priority".to_string());

    let mut res = db::Member::list_groups(
        &app.scylla,
        ctx.user,
        fields,
        page_size,
        token_to_xid(&input.page_token),
        input.status,
    )
    .await?;

    let next_page_token = if res.len() >= page_size as usize {
        let v = res.last().unwrap();
        to.with_option(token_from_xid(v.id))
    } else {
        None
    };

    res.insert(0, usergroup);
    Ok(to.with(SuccessResponse {
        total_size: None,
        next_page_token,
        result: res
            .iter()
            .map(|r| GroupOutput::from(r.to_owned(), &to))
            .collect(),
    }))
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct UserInfo {
    pub id: PackObject<xid::Id>,
    pub cn: String,
    pub status: i8,
    pub kind: i8,
    pub name: String,
    pub picture: String,
}

pub async fn batch_get_info(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<BatchIdsInput>,
) -> Result<PackObject<SuccessResponse<Vec<UserInfo>>>, HTTPError> {
    let (to, input) = to.unpack();
    input.validate()?;

    ctx.set_kvs(vec![
        ("action", "batch_get_info".into()),
        ("ids", input.ids.len().into()),
    ])
    .await;

    let res = db::User::batch_get(
        &app.scylla,
        input.ids,
        vec![
            "id".to_string(),
            "cn".to_string(),
            "status".to_string(),
            "kind".to_string(),
            "name".to_string(),
            "picture".to_string(),
        ],
    )
    .await?;

    let output: Vec<UserInfo> = res
        .into_iter()
        .map(|doc| UserInfo {
            id: to.with(doc.id),
            cn: doc.cn,
            status: doc.status,
            kind: doc.kind,
            name: doc.name,
            picture: doc.picture,
        })
        .collect();

    Ok(to.with(SuccessResponse::new(output)))
}

pub async fn get_group(
    State(app): State<Arc<AppState>>,
    Extension(ctx): Extension<Arc<ReqContext>>,
    to: PackObject<()>,
    input: Query<QueryGid>,
) -> Result<PackObject<SuccessResponse<GroupOutput>>, HTTPError> {
    input.validate()?;

    let gid = *input.gid.to_owned();
    ctx.set_kvs(vec![
        ("action", "get_group".into()),
        ("gid", gid.to_string().into()),
    ])
    .await;

    let (role, priority) = if gid == ctx.user {
        (2i8, 2i8)
    } else {
        let mut member = db::Member::with_pk(gid, ctx.user);
        let res = member.get_one(&app.scylla, vec!["role".to_string()]).await;
        if res.is_err() || member.role < -1 {
            return Err(HTTPError::new(403, "not a group member".to_string()));
        }

        (member.role, member.priority)
    };

    let mut doc = db::Group::with_pk(gid);
    doc.get_one(&app.scylla, get_fields(input.fields.clone()))
        .await?;
    doc._role = role;
    doc._priority = priority;
    doc._fields.push("_role".to_string());
    doc._fields.push("_priority".to_string());
    Ok(to.with(SuccessResponse::new(GroupOutput::from(doc, &to))))
}
