use isolang::Language;

use axum_web::context::unix_ms;
use axum_web::erring::HTTPError;
use scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use crate::db::{
    scylladb,
    scylladb::{extract_applied, Query},
    xid_to_cn,
};

#[derive(Debug, Default, Clone, CqlOrm)]
pub struct UserIndex {
    pub cn: String, // should be lowercase
    pub id: xid::Id,
    pub created_at: i64,
    pub expire_at: i64,

    pub _fields: Vec<String>, // selected fields，`_` 前缀字段会被 CqlOrm 忽略
}

impl UserIndex {
    pub fn with_pk(cn: String) -> Self {
        Self {
            cn,
            ..Default::default()
        }
    }

    pub async fn get_one(&mut self, db: &scylladb::ScyllaDB) -> anyhow::Result<()> {
        self._fields = Self::fields();

        let query = "SELECT id,created_at,expire_at FROM user_index WHERE cn=? LIMIT 1";
        let params = (&self.cn,);
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(2);
        cols.fill(
            res,
            &vec![
                "id".to_string(),
                "created_at".to_string(),
                "expire_at".to_string(),
            ],
        )?;
        self.fill(&cols);

        Ok(())
    }

    async fn save(&mut self, db: &scylladb::ScyllaDB, expire_ms: i64) -> anyhow::Result<bool> {
        self._fields = Self::fields();
        let now = unix_ms() as i64;
        self.created_at = now;
        self.expire_at = now + expire_ms;
        let query =
            "INSERT INTO user_index (cn,id,created_at,expire_at) VALUES (?,?,?,?) IF NOT EXISTS";
        let params = (&self.cn, self.id.to_cql(), self.created_at, self.expire_at);
        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(409, format!("{} already exists", self.id)).into());
        }

        Ok(true)
    }

    async fn update_expire(
        &mut self,
        db: &scylladb::ScyllaDB,
        expire_at: i64,
    ) -> anyhow::Result<bool> {
        let now = unix_ms() as i64;
        if expire_at < now {
            return Err(HTTPError::new(
                400,
                format!("Invalid expire_at, expected >= {}, got {}", now, expire_at),
            )
            .into());
        }

        self.get_one(db).await?;
        if self.expire_at == expire_at {
            return Ok(false); // no need to update
        }

        let query = "UPDATE user_index SET expire_at=? WHERE cn=? IF EXISTS";
        let params = (expire_at, &self.cn);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "Update user_index {} expire_at failed, please try again",
                    self.cn
                ),
            )
            .into());
        }

        self.expire_at = expire_at;
        Ok(true)
    }

    async fn reset_cn(&mut self, db: &scylladb::ScyllaDB, id: xid::Id) -> anyhow::Result<bool> {
        self.get_one(db).await?;
        let now = unix_ms() as i64;
        if self.expire_at == 0 || self.expire_at + 1000 * 3600 * 24 * 365 > now {
            return Err(HTTPError::new(
                409,
                format!(
                    "User common name {} is bundling to {}, can't reset to {}",
                    self.cn, self.id, id
                ),
            )
            .into());
        }

        if self.id == id {
            return Ok(false); // no need to update
        }

        let query = "UPDATE user_index SET id=?,expire_at=? WHERE cn=? IF EXISTS";
        let params = (id.to_cql(), self.expire_at, &self.cn);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "reset user {} with id {} failed, please try again",
                    self.cn, id
                ),
            )
            .into());
        }

        self.id = id;
        Ok(true)
    }
}

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct User {
    pub id: xid::Id,
    pub cn: String, // should be lowercase
    pub gid: xid::Id,
    pub status: i8,
    pub rating: i8,
    pub kind: i8,
    pub created_at: i64,
    pub updated_at: i64,
    pub email: String,
    pub phone: String,
    pub name: String,
    pub birthdate: String, // yyyy-mm-dd
    pub locale: Language,
    pub picture: String,
    pub address: String,
    pub website: String,
    pub bio: Vec<u8>,

    pub _fields: Vec<String>, // selected fields，`_` 前缀字段会被 CqlOrm 忽略
}

impl User {
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

        let mut select_fields = select_fields;
        let field = "cn".to_string();
        if !select_fields.contains(&field) {
            select_fields.push(field);
        }
        let field = "gid".to_string();
        if !select_fields.contains(&field) {
            select_fields.push(field);
        }

        if with_pk {
            let field = "id".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
        }

        Ok(select_fields)
    }

    pub fn status_name(&self) -> String {
        match self.status {
            -2 => "Disabled".to_string(),
            -1 => "Suspended".to_string(),
            0 => "Normal".to_string(),
            1 => "Verified".to_string(),
            2 => "Protected".to_string(),
            _ => "Unknown".to_string(),
        }
    }

    pub fn valid_status(&self, status: i8) -> anyhow::Result<()> {
        if !(-2..=2).contains(&status) {
            return Err(HTTPError::new(400, format!("Invalid status, {}", status)).into());
        }

        match self.status {
            -2 if !(-1..=0).contains(&status) => Err(HTTPError::new(
                400,
                format!(
                    "User status is {}, expected update to -1 or 0, got {}",
                    self.status, status
                ),
            )
            .into()),
            -1 if !(-2..=0).contains(&status) => Err(HTTPError::new(
                400,
                format!(
                    "User status is {}, expected update to -2..=0, got {}",
                    self.status, status
                ),
            )
            .into()),
            0 if !(-1..=2).contains(&status) => Err(HTTPError::new(
                400,
                format!(
                    "User status is {}, expected update to -1..=2, got {}",
                    self.status, status
                ),
            )
            .into()),
            1 if !(-1..=2).contains(&status) => Err(HTTPError::new(
                400,
                format!(
                    "User status is {}, expected update to -1..=2, got {}",
                    self.status, status
                ),
            )
            .into()),
            2 if !(-1..=2).contains(&status) => Err(HTTPError::new(
                400,
                format!(
                    "User status is {}, expected update to -1..=2, got {}",
                    self.status, status
                ),
            )
            .into()),
            _ => Ok(()),
        }
    }

    pub async fn get_one(
        &mut self,
        db: &scylladb::ScyllaDB,
        select_fields: Vec<String>,
    ) -> anyhow::Result<()> {
        let fields = Self::select_fields(select_fields, false)?;
        self._fields = fields.clone();

        let query = format!("SELECT {} FROM user WHERE id=? LIMIT 1", fields.join(","));
        let params = (self.id.to_cql(),);
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        self.fill(&cols);

        Ok(())
    }

    pub async fn save(&mut self, db: &scylladb::ScyllaDB) -> anyhow::Result<bool> {
        let mut i: u8 = 0;
        let expire: i64 = 1000 * 3600 * 24 * 365 * 99; // default CN expire 99 years
        loop {
            self.cn = xid_to_cn(&self.id, i);

            let mut index = UserIndex::with_pk(self.cn.clone());
            index.id = self.id;
            let res = index.save(db, expire).await;
            if res.is_ok() {
                self.created_at = index.created_at;
                self.updated_at = index.created_at;
                break;
            }

            i += 1;
            if i == u8::MAX {
                return Err(HTTPError::new(500, "Failed to save user".to_string()).into());
            }
        }

        self.rating = 3; // R (Restricted - 17岁及以上适宜)
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
            "INSERT INTO user ({}) VALUES ({}) IF NOT EXISTS",
            cols_name.join(","),
            vals_name.join(",")
        );

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {}, {} save failed, please try again",
                    self.id, self.cn
                ),
            )
            .into());
        }

        Ok(true)
    }

    pub async fn update_cn(
        &mut self,
        db: &scylladb::ScyllaDB,
        cn: String,
        updated_at: i64,
    ) -> anyhow::Result<bool> {
        // TODO: update with UserIndex
        if cn != cn.to_lowercase().trim() {
            return Err(HTTPError::new(400, format!("Invalid cn, {}", cn)).into());
        }

        self.get_one(db, vec!["cn".to_string(), "updated_at".to_string()])
            .await?;
        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} updated_at conflict, expected updated_at {}, got {}",
                    self.id, self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.cn == cn {
            return Ok(false); // no need to update
        }
        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE user SET cn=?,updated_at=? WHERE id=? IF updated_at=?";
        let params = (cn.to_cql(), new_updated_at, self.id.to_cql(), updated_at);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!("User {} update_cn {} failed, please try again", self.id, cn),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        self.cn = cn;
        Ok(true)
    }

    pub async fn update_status(
        &mut self,
        db: &scylladb::ScyllaDB,
        status: i8,
        updated_at: i64,
    ) -> anyhow::Result<bool> {
        self.get_one(db, vec!["status".to_string(), "updated_at".to_string()])
            .await?;
        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} updated_at conflict, expected updated_at {}, got {}",
                    self.id, self.updated_at, updated_at
                ),
            )
            .into());
        }
        self.valid_status(status)?;

        if self.status == status {
            return Ok(false); // no need to update
        }
        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE user SET status=?,updated_at=? WHERE id=? IF updated_at=?";
        let params = (status, new_updated_at, self.id.to_cql(), updated_at);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} update_status {} failed, please try again",
                    self.id, status
                ),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        self.status = status;
        Ok(true)
    }

    pub async fn update_rating(
        &mut self,
        db: &scylladb::ScyllaDB,
        rating: i8,
        updated_at: i64,
    ) -> anyhow::Result<bool> {
        self.get_one(db, vec!["rating".to_string(), "updated_at".to_string()])
            .await?;
        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} updated_at conflict, expected updated_at {}, got {}",
                    self.id, self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.rating == rating {
            return Ok(false); // no need to update
        }
        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE user SET rating=?,updated_at=? WHERE id=? IF updated_at=?";
        let params = (rating, new_updated_at, self.id.to_cql(), updated_at);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} update_rating {} failed, please try again",
                    self.id, rating
                ),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        self.rating = rating;
        Ok(true)
    }

    pub async fn update_kind(
        &mut self,
        db: &scylladb::ScyllaDB,
        kind: i8,
        updated_at: i64,
    ) -> anyhow::Result<bool> {
        self.get_one(db, vec!["kind".to_string(), "updated_at".to_string()])
            .await?;
        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} updated_at conflict, expected updated_at {}, got {}",
                    self.id, self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.kind == kind {
            return Ok(false); // no need to update
        }
        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE user SET kind=?,updated_at=? WHERE id=? IF updated_at=?";
        let params = (kind, new_updated_at, self.id.to_cql(), updated_at);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} update_kind {} failed, please try again",
                    self.id, kind
                ),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        self.kind = kind;
        Ok(true)
    }

    pub async fn update_email(
        &mut self,
        db: &scylladb::ScyllaDB,
        email: String,
        updated_at: i64,
    ) -> anyhow::Result<bool> {
        self.get_one(db, vec!["email".to_string(), "updated_at".to_string()])
            .await?;
        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} updated_at conflict, expected updated_at {}, got {}",
                    self.id, self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.email == email {
            return Ok(false); // no need to update
        }
        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE user SET email=?,updated_at=? WHERE id=? IF updated_at=?";
        let params = (email.to_cql(), new_updated_at, self.id.to_cql(), updated_at);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} update_email {} failed, please try again",
                    self.id, email
                ),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        self.email = email;
        Ok(true)
    }

    pub async fn update_phone(
        &mut self,
        db: &scylladb::ScyllaDB,
        phone: String,
        updated_at: i64,
    ) -> anyhow::Result<bool> {
        self.get_one(db, vec!["phone".to_string(), "updated_at".to_string()])
            .await?;
        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} updated_at conflict, expected updated_at {}, got {}",
                    self.id, self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.phone == phone {
            return Ok(false); // no need to update
        }
        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE user SET phone=?,updated_at=? WHERE id=? IF updated_at=?";
        let params = (phone.to_cql(), new_updated_at, self.id.to_cql(), updated_at);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "User {} update_phone {} failed, please try again",
                    self.id, phone
                ),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        self.phone = phone;
        Ok(true)
    }

    pub async fn update(
        &mut self,
        db: &scylladb::ScyllaDB,
        cols: ColumnsMap,
        updated_at: i64,
    ) -> anyhow::Result<bool> {
        let valid_fields = vec![
            "name",
            "birthdate",
            "locale",
            "picture",
            "address",
            "website",
            "bio",
        ];
        let update_fields = cols.keys();
        for field in &update_fields {
            if !valid_fields.contains(&field.as_str()) {
                return Err(HTTPError::new(400, format!("Invalid field: {}", field)).into());
            }
        }

        self.get_one(db, vec!["status".to_string(), "updated_at".to_string()])
            .await?;
        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "User updated_at conflict, expected updated_at {}, got {}",
                    self.updated_at, updated_at
                ),
            )
            .into());
        }
        if self.status < 0 {
            return Err(HTTPError::new(
                409,
                format!("User can not be update, status {}", self.status),
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
            "UPDATE user SET {} WHERE id=? IF updated_at=?",
            set_fields.join(",")
        );
        params.push(self.id.to_cql());
        params.push(updated_at.to_cql());

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!("User {} update failed, please try again", self.id),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        Ok(true)
    }

    pub async fn list_group_users(
        db: &scylladb::ScyllaDB,
        gid: xid::Id,
        select_fields: Vec<String>,
        page_size: u16,
        page_token: Option<xid::Id>,
        status: Option<i8>,
    ) -> anyhow::Result<Vec<User>> {
        let fields = Self::select_fields(select_fields, true)?;

        let rows = if let Some(id) = page_token {
            if status.is_none() {
                let query = Query::new(format!(
                "SELECT {} FROM user WHERE gid=? AND uid<? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                fields.clone().join(",")))
                .with_page_size(page_size as i32);
                let params = (gid.to_cql(), id.to_cql(), page_size as i32);
                db.execute_paged(query, params, None).await?
            } else {
                let query = Query::new(format!(
                    "SELECT {} FROM user WHERE gid=? AND id<? AND status=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                    fields.clone().join(","))).with_page_size(page_size as i32);
                let params = (gid.to_cql(), id.to_cql(), status.unwrap(), page_size as i32);
                db.execute_paged(query, params, None).await?
            }
        } else if status.is_none() {
            let query = Query::new(format!(
                "SELECT {} FROM user WHERE gid=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                fields.clone().join(",")
            ))
            .with_page_size(page_size as i32);
            let params = (gid.to_cql(), page_size as i32);
            db.execute_iter(query, params).await?
        } else {
            let query = Query::new(format!(
                "SELECT {} FROM user WHERE gid=? AND status=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                fields.clone().join(",")
            ))
            .with_page_size(page_size as i32);
            let params = (gid.as_bytes(), status.unwrap(), page_size as i32);
            db.execute_iter(query, params).await?
        };

        let mut res: Vec<User> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = User::default();
            let mut cols = ColumnsMap::with_capacity(fields.len());
            cols.fill(row, &fields)?;
            doc.fill(&cols);
            doc._fields = fields.clone();
            res.push(doc);
        }

        Ok(res)
    }
}
