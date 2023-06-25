use std::collections::HashSet;

use axum_web::context::unix_ms;
use axum_web::erring::HTTPError;
use scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use crate::db::{
    scylladb,
    scylladb::{extract_applied, Query},
};

const SESSION_TTL_DEFAULT: i32 = 3600 * 24 * 30; // 30 days
const SESSION_TTL_MIN: i32 = 3600;
const SESSION_TTL_MAX: i32 = 3600 * 24 * 400; // 400 days

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct AuthN {
    pub idp: String,
    pub aid: String,
    pub oid: String,
    pub uid: xid::Id,
    pub created_at: i64,
    pub updated_at: i64,
    pub expire_at: i64,
    pub scope: HashSet<String>,
    pub ip: String,
    pub payload: Vec<u8>,

    pub _fields: Vec<String>, // selected fields，`_` 前缀字段会被 CqlOrm 忽略
}

impl AuthN {
    pub fn with_pk(idp: String, aid: String, oid: String) -> Self {
        Self {
            idp,
            aid,
            oid,
            ..Default::default()
        }
    }

    pub fn select_fields(select_fields: Vec<String>, with_pk: bool) -> anyhow::Result<Vec<String>> {
        if select_fields.is_empty() {
            return Ok(Self::fields());
        }

        let fields = Self::fields();
        for field in &select_fields {
            if !fields.contains(field) {
                return Err(HTTPError::new(400, format!("Invalid field: {}", field)).into());
            }
        }

        let mut select_fields = select_fields;
        let field = "uid".to_string();
        if !select_fields.contains(&field) {
            select_fields.push(field);
        }

        if with_pk {
            let field = "idp".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            let field = "aid".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            let field = "oid".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            return Ok(select_fields);
        }

        Ok(select_fields)
    }

    pub async fn get_one(
        &mut self,
        db: &scylladb::ScyllaDB,
        select_fields: Vec<String>,
    ) -> anyhow::Result<()> {
        let fields = Self::select_fields(select_fields, false)?;
        self._fields = fields.clone();

        let query = format!(
            "SELECT {} FROM authn WHERE idp=? AND aid=? AND oid=? LIMIT 1",
            fields.join(",")
        );
        let params = (&self.idp, &self.aid, &self.oid);
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        self.fill(&cols);

        Ok(())
    }

    pub async fn save(&mut self, db: &scylladb::ScyllaDB) -> anyhow::Result<bool> {
        let now = unix_ms() as i64;
        self.created_at = now;
        self.updated_at = now;

        let fields = Self::fields();
        self._fields = fields.clone();

        let mut cols_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut vals_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut params: Vec<&CqlValue> = Vec::with_capacity(fields.len());
        let cols = self.to();

        for field in &fields {
            cols_name.push(field);
            vals_name.push("?");
            params.push(cols.get(field).unwrap());
        }

        let query = format!(
            "INSERT INTO authn ({}) VALUES ({}) IF NOT EXISTS",
            cols_name.join(","),
            vals_name.join(",")
        );

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthN {}, {}, {}, {} save failed, please try again",
                    self.idp, self.aid, self.oid, self.uid
                ),
            )
            .into());
        }

        Ok(true)
    }

    pub async fn update(
        &mut self,
        db: &scylladb::ScyllaDB,
        cols: ColumnsMap,
        uid: xid::Id,
    ) -> anyhow::Result<bool> {
        let valid_fields = vec!["expire_at", "scope", "ip", "payload"];
        let update_fields = cols.keys();
        for field in &update_fields {
            if !valid_fields.contains(&field.as_str()) {
                return Err(HTTPError::new(400, format!("Invalid field: {}", field)).into());
            }
        }

        let mut set_fields: Vec<String> = Vec::with_capacity(update_fields.len() + 1);
        let mut params: Vec<CqlValue> = Vec::with_capacity(update_fields.len() + 1 + 4);

        let new_updated_at = unix_ms() as i64;
        set_fields.push("updated_at=?".to_string());
        params.push(new_updated_at.to_cql());

        for field in &update_fields {
            set_fields.push(format!("{}=?", field));
            params.push(cols.get(field).unwrap().to_owned());
        }

        let query = format!(
            "UPDATE authn SET {} WHERE idp=? AND aid=? AND oid=? IF uid=?",
            set_fields.join(",")
        );
        params.push(self.idp.to_cql());
        params.push(self.aid.to_cql());
        params.push(self.oid.to_cql());
        params.push(uid.to_cql());

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthN {}, {}, {} update failed, please try again",
                    self.idp, self.aid, self.oid
                ),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        Ok(true)
    }

    pub async fn delete(&mut self, db: &scylladb::ScyllaDB, uid: xid::Id) -> anyhow::Result<bool> {
        let res = self.get_one(db, vec!["uid".to_string()]).await;
        if res.is_err() {
            return Ok(false); // already deleted
        }

        if self.uid != uid {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthN {}, {}, {} delete conflict, expected uid {}, got {}",
                    self.idp, self.aid, self.oid, self.uid, uid
                ),
            )
            .into());
        }

        let query = "DELETE FROM authn WHERE idp=? AND aid=? AND oid=? IF uid=?";
        let params = (
            self.idp.to_cql(),
            self.aid.to_cql(),
            self.oid.to_cql(),
            uid.to_cql(),
        );
        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthN {}, {}, {} delete failed, please try again",
                    self.idp, self.aid, self.oid
                ),
            )
            .into());
        }

        Ok(true)
    }

    pub async fn list_by_uid(
        db: &scylladb::ScyllaDB,
        uid: xid::Id,
        select_fields: Vec<String>,
    ) -> anyhow::Result<Vec<AuthN>> {
        let fields = Self::select_fields(select_fields, true)?;

        let query = Query::new(format!(
            "SELECT {} FROM authn WHERE uid=? LIMIT 1000 BYPASS CACHE USING TIMEOUT 3s",
            fields.clone().join(",")
        ))
        .with_page_size(1000i32);
        let params = (uid.to_cql(),);
        let rows = db.execute_iter(query, params).await?;

        let mut res: Vec<AuthN> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = AuthN::default();
            let mut cols = ColumnsMap::with_capacity(fields.len());
            cols.fill(row, &fields)?;
            doc.fill(&cols);
            doc._fields = fields.clone();
            res.push(doc);
        }

        Ok(res)
    }
}

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct AuthZ {
    pub oid: uuid::Uuid,
    pub aid: xid::Id,
    pub uid: xid::Id,
    pub created_at: i64,
    pub updated_at: i64,
    pub expire_at: i64,
    pub scope: HashSet<String>,
    pub ip: String,

    pub _fields: Vec<String>, // selected fields，`_` 前缀字段会被 CqlOrm 忽略
}

impl AuthZ {
    pub fn with_pk(oid: uuid::Uuid, aid: xid::Id) -> Self {
        Self {
            oid,
            aid,
            ..Default::default()
        }
    }

    pub fn select_fields(select_fields: Vec<String>, with_pk: bool) -> anyhow::Result<Vec<String>> {
        if select_fields.is_empty() {
            return Ok(Self::fields());
        }

        let fields = Self::fields();
        for field in &select_fields {
            if !fields.contains(field) {
                return Err(HTTPError::new(400, format!("Invalid field: {}", field)).into());
            }
        }

        if with_pk {
            let mut select_fields = select_fields;
            let field = "oid".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            let field = "aid".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            return Ok(select_fields);
        }

        Ok(select_fields)
    }

    pub async fn get_one(
        &mut self,
        db: &scylladb::ScyllaDB,
        select_fields: Vec<String>,
    ) -> anyhow::Result<()> {
        let fields = Self::select_fields(select_fields, false)?;
        self._fields = fields.clone();

        let query = format!(
            "SELECT {} FROM authz WHERE oid=? AND aid=? LIMIT 1",
            fields.join(",")
        );
        let params = (self.oid.to_cql(), self.aid.to_cql());
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        self.fill(&cols);

        Ok(())
    }

    pub async fn save(&mut self, db: &scylladb::ScyllaDB) -> anyhow::Result<bool> {
        let now = unix_ms() as i64;
        self.created_at = now;
        self.updated_at = now;

        let fields = Self::fields();
        self._fields = fields.clone();

        let mut cols_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut vals_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut params: Vec<&CqlValue> = Vec::with_capacity(fields.len());
        let cols = self.to();

        for field in &fields {
            cols_name.push(field);
            vals_name.push("?");
            params.push(cols.get(field).unwrap());
        }

        let query = format!(
            "INSERT INTO authz ({}) VALUES ({}) IF NOT EXISTS",
            cols_name.join(","),
            vals_name.join(",")
        );

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthZ {}, {}, {} save failed, please try again",
                    self.oid, self.aid, self.uid
                ),
            )
            .into());
        }

        Ok(true)
    }

    pub async fn update(
        &mut self,
        db: &scylladb::ScyllaDB,
        cols: ColumnsMap,
        uid: xid::Id,
    ) -> anyhow::Result<bool> {
        let valid_fields = vec!["expire_at", "scope", "ip"];
        let update_fields = cols.keys();
        for field in &update_fields {
            if !valid_fields.contains(&field.as_str()) {
                return Err(HTTPError::new(400, format!("Invalid field: {}", field)).into());
            }
        }

        self.get_one(db, vec!["uid".to_string()]).await?;
        if self.uid != uid {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthZ {}, {} updated conflict, expected {}, got {}",
                    self.oid, self.aid, self.uid, uid
                ),
            )
            .into());
        }

        let mut set_fields: Vec<String> = Vec::with_capacity(update_fields.len() + 1);
        let mut params: Vec<CqlValue> = Vec::with_capacity(update_fields.len() + 1 + 2);

        let new_updated_at = unix_ms() as i64;
        set_fields.push("updated_at=?".to_string());
        params.push(new_updated_at.to_cql());

        for field in &update_fields {
            set_fields.push(format!("{}=?", field));
            params.push(cols.get(field).unwrap().to_owned());
        }

        let query = format!(
            "UPDATE authz SET {} WHERE oid=? AND aid=? IF EXISTS",
            set_fields.join(",")
        );
        params.push(self.oid.to_cql());
        params.push(self.aid.to_cql());

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthZ {}, {} update failed, please try again",
                    self.oid, self.aid
                ),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        Ok(true)
    }

    pub async fn list_by_uid(
        db: &scylladb::ScyllaDB,
        uid: xid::Id,
        select_fields: Vec<String>,
    ) -> anyhow::Result<Vec<AuthZ>> {
        let fields = Self::select_fields(select_fields, true)?;

        let query = Query::new(format!(
            "SELECT {} FROM authz WHERE uid=? LIMIT 1000 BYPASS CACHE USING TIMEOUT 3s",
            fields.clone().join(",")
        ))
        .with_page_size(1000i32);
        let params = (uid.to_cql(),);
        let rows = db.execute_iter(query, params).await?;

        let mut res: Vec<AuthZ> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = AuthZ::default();
            let mut cols = ColumnsMap::with_capacity(fields.len());
            cols.fill(row, &fields)?;
            doc.fill(&cols);
            doc._fields = fields.clone();
            res.push(doc);
        }

        Ok(res)
    }
}

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct Session {
    pub id: xid::Id,
    pub uid: xid::Id,
    pub ip: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub ttl: i32,
    pub device_id: String,
    pub device_desc: String,
    pub idp: String,
    pub aid: String,
    pub oid: String,

    pub _fields: Vec<String>, // selected fields，`_` 前缀字段会被 CqlOrm 忽略
}

impl Session {
    pub fn with_pk(id: xid::Id) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    pub fn select_fields(select_fields: Vec<String>, with_pk: bool) -> anyhow::Result<Vec<String>> {
        if select_fields.is_empty() {
            return Ok(Self::fields());
        }

        let fields = Self::fields();
        for field in &select_fields {
            if !fields.contains(field) {
                return Err(HTTPError::new(400, format!("Invalid field: {}", field)).into());
            }
        }

        if with_pk {
            let mut select_fields = select_fields;
            let field = "id".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            return Ok(select_fields);
        }

        Ok(select_fields)
    }

    pub async fn get_one(
        &mut self,
        db: &scylladb::ScyllaDB,
        select_fields: Vec<String>,
    ) -> anyhow::Result<()> {
        let fields = Self::select_fields(select_fields, false)?;
        self._fields = fields.clone();

        let query = format!(
            "SELECT {} FROM session WHERE id=? LIMIT 1",
            fields.join(",")
        );
        let params = (self.id.to_cql(),);
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        self.fill(&cols);

        Ok(())
    }

    pub async fn save(&mut self, db: &scylladb::ScyllaDB, ttl: i32) -> anyhow::Result<bool> {
        let now = unix_ms() as i64;
        self.created_at = now;
        self.updated_at = now;
        self.ttl = if ttl < SESSION_TTL_MIN {
            SESSION_TTL_DEFAULT
        } else if ttl > SESSION_TTL_MAX {
            SESSION_TTL_MAX
        } else {
            ttl
        };

        let fields = Self::fields();
        self._fields = fields.clone();

        let mut cols_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut vals_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut params: Vec<&CqlValue> = Vec::with_capacity(fields.len() + 1);
        let cols = self.to();

        for field in &fields {
            cols_name.push(field);
            vals_name.push("?");
            params.push(cols.get(field).unwrap());
        }

        let query = format!(
            "INSERT INTO session ({}) VALUES ({}) USING TTL ? IF NOT EXISTS",
            cols_name.join(","),
            vals_name.join(",")
        );

        let ttl = self.ttl.to_cql();
        params.push(&ttl);
        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "Session {}, {} save failed, please try again",
                    self.id, self.uid
                ),
            )
            .into());
        }

        Ok(true)
    }

    pub async fn renew(&mut self, db: &scylladb::ScyllaDB) -> anyhow::Result<bool> {
        self.get_one(db, vec![]).await?;

        let now = unix_ms() as i64;
        self.created_at = now; // renew time
        self.updated_at = now;

        let fields = self._fields.clone();
        let mut cols_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut vals_name: Vec<&str> = Vec::with_capacity(fields.len());
        let mut params: Vec<&CqlValue> = Vec::with_capacity(fields.len() + 1);
        let cols = self.to();

        for field in &fields {
            cols_name.push(field);
            vals_name.push("?");
            params.push(cols.get(field).unwrap());
        }

        let query = format!(
            "INSERT INTO session ({}) VALUES ({}) USING TTL ? IF EXISTS",
            cols_name.join(","),
            vals_name.join(",")
        );

        let ttl = self.ttl.to_cql();
        params.push(&ttl);
        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "Session {}, {} renew failed, please try again",
                    self.id, self.uid
                ),
            )
            .into());
        }

        Ok(true)
    }

    pub async fn update_ip(&mut self, db: &scylladb::ScyllaDB, ip: String) -> anyhow::Result<bool> {
        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE session SET ip=?,updated_at=? WHERE id=? IF EXISTS".to_string();
        let params = (ip, new_updated_at, self.id.to_cql());

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!("Session {} update ip failed, please try again", self.id),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        Ok(true)
    }

    pub async fn delete(&mut self, db: &scylladb::ScyllaDB, uid: xid::Id) -> anyhow::Result<bool> {
        let res = self.get_one(db, vec!["uid".to_string()]).await;
        if res.is_err() {
            return Ok(false); // already deleted
        }

        if self.uid != uid {
            return Err(HTTPError::new(
                409,
                format!(
                    "Session {} delete conflict, expected uid {}, got {}",
                    self.id, self.uid, uid
                ),
            )
            .into());
        }

        let query = "DELETE FROM session WHERE id=? IF uid=?";
        let params = (self.id.to_cql(), uid.to_cql());
        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!("Session {} delete failed, please try again", self.id),
            )
            .into());
        }

        Ok(true)
    }

    pub async fn list_by_uid(
        db: &scylladb::ScyllaDB,
        uid: xid::Id,
        select_fields: Vec<String>,
    ) -> anyhow::Result<Vec<Session>> {
        let fields = Self::select_fields(select_fields, true)?;

        let query = Query::new(format!(
            "SELECT {} FROM session WHERE uid=? LIMIT 1000 BYPASS CACHE USING TIMEOUT 3s",
            fields.clone().join(",")
        ))
        .with_page_size(1000i32);
        let params = (uid.to_cql(),);
        let rows = db.execute_iter(query, params).await?;

        let mut res: Vec<Session> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = Session::default();
            let mut cols = ColumnsMap::with_capacity(fields.len());
            cols.fill(row, &fields)?;
            doc.fill(&cols);
            doc._fields = fields.clone();
            res.push(doc);
        }

        Ok(res)
    }
}
