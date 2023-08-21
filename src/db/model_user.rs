use chrono::{NaiveDate, NaiveDateTime};
use isolang::Language;

use axum_web::{context::unix_ms, erring::HTTPError, object::PackObject};
use scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use crate::db::{scylladb, scylladb::extract_applied, xid_to_cn};

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
        let params = (&self.cn.to_lowercase(),);
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
        let params = (
            &self.cn.to_lowercase(),
            self.id.to_cql(),
            self.created_at,
            self.expire_at,
        );
        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(409, format!("{} already exists", self.cn)).into());
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
        let params = (expire_at, &self.cn.to_lowercase());

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

    async fn reset_cn(
        &mut self,
        db: &scylladb::ScyllaDB,
        id: xid::Id,
        expire_at: i64,
    ) -> anyhow::Result<bool> {
        self.get_one(db).await?;
        if self.id == id {
            return Ok(false); // no need to update
        }

        let now = unix_ms() as i64;
        // 过期一年才能被重置
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

        self.expire_at = now + expire_at;
        let query = "UPDATE user_index SET id=?,expire_at=? WHERE cn=? IF EXISTS";
        let params = (id.to_cql(), self.expire_at, &self.cn.to_lowercase());

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
    pub kind: i8,
    pub rating: i8,
    pub created_at: i64,
    pub updated_at: i64,
    pub email: String,
    pub phone: String,
    pub name: String,
    pub birthdate: i32,
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

    pub fn get_rating(&self) -> i8 {
        if self.rating > 0 || self.birthdate <= 0 {
            return self.rating;
        }

        let nowdate = NaiveDateTime::from_timestamp_millis(unix_ms() as i64)
            .unwrap()
            .date();
        let birthdate = NaiveDate::from_num_days_from_ce_opt(self.birthdate).unwrap_or_default();

        // TODO，如何定级？
        //    - G (General Audience - 全年龄适宜)
        //    - PG (Parental Guidance)
        //    - PG-13 (Parents Strongly Cautioned)
        //    - R (Restricted)
        //    - NC-17 (Adults Only - 仅限成人)
        match nowdate.years_since(birthdate).unwrap_or(0) {
            18.. => 3,
            13.. => 2,
            8.. => 1,
            _ => 0,
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
        let mut doc = Self::with_pk(self.id);
        if doc.get_one(db, vec!["cn".to_string()]).await.is_ok() {
            return Err(HTTPError::new(409, format!("User {}, {} exists", doc.id, doc.cn)).into());
        }

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

        let mut doc = UserIndex::with_pk(cn.clone());
        doc.get_one(db).await?;
        if doc.id != self.id {
            return Err(HTTPError::new(409, format!("User {} exists", doc.cn)).into());
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
        if rating < 0 {
            return Err(HTTPError::new(400, format!("Invalid rating, {}", rating)).into());
        }

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
        if !(-1..=4).contains(&kind) {
            return Err(HTTPError::new(400, format!("Invalid kind, {}", kind)).into());
        }

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
        if email != email.to_lowercase().trim() {
            return Err(HTTPError::new(400, format!("Invalid email, {}", email)).into());
        }

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
        if phone != phone.to_lowercase().trim() {
            return Err(HTTPError::new(400, format!("Invalid phone, {}", phone)).into());
        }

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

        let id_fields = vec!["id".to_string()];

        let rows = if status.is_none() {
            let query = format!(
                "SELECT {} FROM user WHERE gid=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                id_fields.clone().join(",")
            );
            let params = (gid.to_cql(), 1000i32);
            db.execute_iter(query, params).await?
        } else {
            let query = format!(
                "SELECT {} FROM user WHERE gid=? AND status=? LIMIT ? ALLOW FILTERING BYPASS CACHE USING TIMEOUT 3s", id_fields.clone().join(","));
            let params = (gid.to_cql(), status.unwrap(), 1000i32);
            db.execute_iter(query, params).await?
        };

        let mut users: Vec<User> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = User::default();
            let mut cols = ColumnsMap::with_capacity(1);
            cols.fill(row, &id_fields)?;
            doc.fill(&cols);
            doc._fields = id_fields.clone();
            users.push(doc);
        }

        users.sort_by(|a, b| b.id.partial_cmp(&a.id).unwrap());
        if !users.is_empty() {
            if let Some(id) = page_token {
                if users.last().unwrap().id >= id {
                    users.truncate(0);
                } else if users.first().unwrap().id >= id {
                    let mut iter = users.split_inclusive(|u| u.id == id).skip(1);
                    if let Some(rt) = iter.next() {
                        if !rt.is_empty() {
                            users = rt.to_vec();
                        }
                    }
                }
            }
        }

        if users.len() > page_size as usize {
            users.truncate(page_size as usize);
        }

        let mut res: Vec<User> = Vec::with_capacity(users.len());
        for u in users {
            let mut doc = User::with_pk(u.id);
            doc.get_one(db, fields.clone()).await?;
            doc._fields = fields.clone();
            res.push(doc);
        }

        Ok(res)
    }

    pub async fn batch_get(
        db: &scylladb::ScyllaDB,
        ids: Vec<PackObject<xid::Id>>,
        select_fields: Vec<String>,
    ) -> anyhow::Result<Vec<User>> {
        let fields = Self::select_fields(select_fields, false)?;

        let query = format!(
            "SELECT {} FROM user WHERE id IN ({}) BYPASS CACHE USING TIMEOUT 3s",
            fields.clone().join(","),
            ids.iter().map(|_| "?").collect::<Vec<&str>>().join(",")
        );
        let params = ids
            .into_iter()
            .map(|id| id.to_cql())
            .collect::<Vec<CqlValue>>();
        let rows = db.execute_iter(query, params).await?;

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

#[cfg(test)]
mod tests {
    use axum_web::erring;
    use chrono::Datelike;
    use ciborium::cbor;

    use tokio::sync::OnceCell;

    use super::*;
    use crate::conf;
    use crate::db;

    static DB: OnceCell<db::scylladb::ScyllaDB> = OnceCell::const_new();

    async fn get_db() -> &'static db::scylladb::ScyllaDB {
        DB.get_or_init(|| async {
            let cfg = conf::Conf::new().unwrap_or_else(|err| panic!("config error: {}", err));
            let res = db::scylladb::ScyllaDB::new(cfg.scylla, "userbase_test").await;
            res.unwrap()
        })
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn test_all() {
        // problem: https://users.rust-lang.org/t/tokio-runtimes-and-tokio-oncecell/91351/5
        user_index_model_works().await;
        user_model_works().await;
        list_group_users_works().await;
        batch_get_users_works().await;
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn user_index_model_works() {
        let db = get_db().await;

        let id = xid::new();
        let mut c1 = UserIndex {
            cn: xid_to_cn(&id, 0),
            id,
            ..Default::default()
        };
        c1.save(db, 1000 * 3600).await.unwrap();

        let id = xid::new();
        let mut c2 = UserIndex {
            cn: xid_to_cn(&id, 0),
            id,
            ..Default::default()
        };
        c2.save(db, 1000 * 3600).await.unwrap();

        let id = xid::new();
        let mut c3 = UserIndex {
            cn: xid_to_cn(&id, 0),
            id,
            ..Default::default()
        };
        c3.save(db, 1000 * 3600).await.unwrap();

        let mut d1 = UserIndex::with_pk(c1.cn);
        d1.get_one(db).await.unwrap();
        assert_eq!(d1.id, c1.id);
        assert_eq!(d1.created_at + 1000 * 3600, d1.expire_at);

        let mut d2 = UserIndex::with_pk(c2.cn);
        d2.get_one(db).await.unwrap();
        assert_eq!(d2.id, c2.id);
        assert_eq!(d2.created_at + 1000 * 3600, d2.expire_at);

        let mut d3 = UserIndex::with_pk(c3.cn);
        let res = d3.update_expire(db, c3.created_at - 1).await;
        assert!(res.is_err());
        let err: erring::HTTPError = res.unwrap_err().into();
        assert_eq!(err.code, 400);

        let res = d3.update_expire(db, c3.expire_at).await.unwrap();
        assert!(!res);

        let res = d3.update_expire(db, c3.expire_at + 3600).await.unwrap();
        assert!(res);

        d3.get_one(db).await.unwrap();
        assert_eq!(d3.id, c3.id);
        assert_eq!(d3.expire_at, c3.expire_at + 3600);

        let new_user = xid::new();
        let res = d3.reset_cn(db, new_user, 1).await;
        assert!(res.is_err());
        let err: erring::HTTPError = res.unwrap_err().into();
        assert_eq!(err.code, 409);

        let query = "UPDATE user_index SET expire_at=? WHERE cn=? IF EXISTS";
        let params = (unix_ms() as i64 - 1000 * 3600 * 24 * 365 - 1, &d3.cn);
        db.execute(query, params).await.unwrap();

        let res = d3.reset_cn(db, new_user, 1).await.unwrap();
        assert!(res);

        let res = d3.reset_cn(db, new_user, 1).await.unwrap();
        assert!(!res);
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn user_model_works() {
        let db = get_db().await;
        let uid = xid::new();

        // valid_status
        {
            let mut doc = User::with_pk(uid);
            assert!(doc.valid_status(-3).is_err());
            assert!(doc.valid_status(-2).is_err());
            assert!(doc.valid_status(-1).is_ok());
            assert!(doc.valid_status(0).is_ok());
            assert!(doc.valid_status(1).is_ok());
            assert!(doc.valid_status(2).is_ok());
            assert!(doc.valid_status(3).is_err());

            doc.status = -1;
            assert!(doc.valid_status(-2).is_ok());
            assert!(doc.valid_status(-1).is_ok());
            assert!(doc.valid_status(0).is_ok());
            assert!(doc.valid_status(1).is_err());
            assert!(doc.valid_status(2).is_err());
            assert!(doc.valid_status(3).is_err());

            doc.status = 1;
            assert!(doc.valid_status(-2).is_err());
            assert!(doc.valid_status(-1).is_ok());
            assert!(doc.valid_status(0).is_ok());
            assert!(doc.valid_status(1).is_ok());
            assert!(doc.valid_status(2).is_ok());
            assert!(doc.valid_status(3).is_err());

            doc.status = 2;
            assert!(doc.valid_status(-2).is_err());
            assert!(doc.valid_status(-1).is_ok());
            assert!(doc.valid_status(0).is_ok());
            assert!(doc.valid_status(1).is_ok());
            assert!(doc.valid_status(2).is_ok());
            assert!(doc.valid_status(3).is_err());
        }

        // get_rating
        {
            let mut doc = User::with_pk(uid);
            assert_eq!(doc.get_rating(), 0i8);
            doc.rating = 1;
            assert_eq!(doc.get_rating(), 1i8);
            doc.rating = 0;
            doc.birthdate = 1;
            assert_eq!(doc.get_rating(), 3i8);

            let nowyear = NaiveDateTime::from_timestamp_millis(unix_ms() as i64)
                .unwrap()
                .date();
            let nowyear = nowyear.year();

            doc.birthdate = NaiveDate::from_ymd_opt(nowyear - 18, 1, 1)
                .unwrap()
                .num_days_from_ce();
            assert_eq!(doc.get_rating(), 3i8);

            doc.birthdate = NaiveDate::from_ymd_opt(nowyear - 17, 1, 1)
                .unwrap()
                .num_days_from_ce();
            assert_eq!(doc.get_rating(), 2i8);

            doc.birthdate = NaiveDate::from_ymd_opt(nowyear - 12, 1, 1)
                .unwrap()
                .num_days_from_ce();
            assert_eq!(doc.get_rating(), 1i8);

            doc.birthdate = NaiveDate::from_ymd_opt(nowyear - 7, 1, 1)
                .unwrap()
                .num_days_from_ce();
            assert_eq!(doc.get_rating(), 0i8);
        }

        // create
        {
            let mut doc = User::with_pk(uid);
            doc.gid = uid;
            doc.name = "Jarvis".to_string();
            doc.birthdate = NaiveDate::default().num_days_from_ce();
            doc.locale = Language::Eng;

            let res = doc.get_one(db, vec![]).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);

            assert!(doc.save(db).await.unwrap());
            assert_eq!(doc.cn, xid_to_cn(&doc.id, 0));
            assert_eq!(doc.gid, doc.id);

            let res = doc.save(db).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into(); // can not insert twice
            assert_eq!(err.code, 409);

            let mut doc2 = User::with_pk(uid);
            doc2.get_one(db, vec![]).await.unwrap();
            // println!("doc: {:#?}", doc2);

            assert_eq!(doc2.name.as_str(), "Jarvis");
            assert_eq!(doc2.locale, Language::Eng);
            assert_eq!(doc2.id, doc.gid);
            assert_eq!(doc2.cn, doc.cn);

            let mut doc3 = User::with_pk(uid);
            doc3.get_one(db, vec!["name".to_string()]).await.unwrap();
            assert_eq!(doc3.name.as_str(), "Jarvis");
            assert_eq!(doc3.locale, Language::default());
            assert_eq!(doc3.id, doc.gid);
            assert_eq!(doc3.cn, doc.cn);
            assert_eq!(doc3._fields, vec!["name", "cn", "gid"]);
        }

        // update_cn
        {
            let mut doc = User::with_pk(uid);
            doc.get_one(db, vec![]).await.unwrap();

            let cn = doc.cn.clone() + "jarvis";

            let res = doc
                .update_cn(db, "Jarvis".to_string(), doc.updated_at)
                .await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 400);

            let res = doc.update_cn(db, cn.clone(), doc.updated_at - 1).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 409);

            let res = doc
                .update_cn(db, doc.cn.clone(), doc.updated_at)
                .await
                .unwrap();
            assert!(!res);

            let res = doc
                .update_cn(db, "jarvis".to_string(), doc.updated_at - 1)
                .await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 409);

            let res = doc.update_cn(db, cn.clone(), doc.updated_at).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);

            let mut index = UserIndex {
                cn: cn.clone(),
                id: uid,
                ..Default::default()
            };
            index.save(db, 1000 * 3600).await.unwrap();
            let res = doc.update_cn(db, cn.clone(), doc.updated_at).await.unwrap();
            assert!(res);
        }

        // update status
        {
            let mut doc = User::with_pk(uid);
            doc.get_one(db, vec![]).await.unwrap();

            let res = doc.update_status(db, 2, doc.updated_at - 1).await;
            assert!(res.is_err());

            let res = doc.update_status(db, 2, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.update_status(db, 1, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.update_status(db, 1, doc.updated_at).await.unwrap();
            assert!(!res);
        }

        // update rating
        {
            let mut doc = User::with_pk(uid);
            doc.get_one(db, vec![]).await.unwrap();

            let res = doc.update_rating(db, -1, doc.updated_at).await;
            assert!(res.is_err());

            let res = doc.update_rating(db, 2, doc.updated_at - 1).await;
            assert!(res.is_err());

            let res = doc.update_rating(db, 2, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.update_rating(db, 1, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.update_rating(db, 1, doc.updated_at).await.unwrap();
            assert!(!res);
        }

        // update kind
        {
            let mut doc = User::with_pk(uid);
            doc.get_one(db, vec![]).await.unwrap();
            let res = doc.update_kind(db, -2, doc.updated_at).await;
            assert!(res.is_err());
            let res = doc.update_kind(db, 5, doc.updated_at).await;
            assert!(res.is_err());

            let res = doc.update_kind(db, 2, doc.updated_at - 1).await;
            assert!(res.is_err());

            let res = doc.update_kind(db, 2, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.update_kind(db, 1, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.update_kind(db, 1, doc.updated_at).await.unwrap();
            assert!(!res);
        }

        // update email
        {
            let mut doc = User::with_pk(uid);
            doc.get_one(db, vec![]).await.unwrap();

            let res = doc
                .update_email(db, "Jarvis@yiwen.ai".to_string(), doc.updated_at)
                .await;
            assert!(res.is_err());
            let res = doc
                .update_email(db, " jarvis@yiwen.ai".to_string(), doc.updated_at)
                .await;
            assert!(res.is_err());

            let res = doc
                .update_email(db, "jarvis@yiwen.ai".to_string(), doc.updated_at - 1)
                .await;
            assert!(res.is_err());

            let res = doc
                .update_email(db, "jarvis@yiwen.ai".to_string(), doc.updated_at)
                .await
                .unwrap();
            assert!(res);

            let res = doc
                .update_email(db, "jarvis2@yiwen.ai".to_string(), doc.updated_at)
                .await
                .unwrap();
            assert!(res);

            let res = doc
                .update_email(db, "jarvis2@yiwen.ai".to_string(), doc.updated_at)
                .await
                .unwrap();
            assert!(!res);
        }

        // update phone
        {
            let mut doc = User::with_pk(uid);
            doc.get_one(db, vec![]).await.unwrap();

            let res = doc
                .update_phone(db, "+86 18812345678 ".to_string(), doc.updated_at)
                .await;
            assert!(res.is_err());

            let res = doc
                .update_phone(db, "+86 18812345678".to_string(), doc.updated_at - 1)
                .await;
            assert!(res.is_err());

            let res = doc
                .update_phone(db, "+86 18812345678".to_string(), doc.updated_at)
                .await
                .unwrap();
            assert!(res);

            let res = doc
                .update_phone(db, "+86 18812345678".to_string(), doc.updated_at)
                .await
                .unwrap();
            assert!(!res);
        }

        // update
        {
            let mut doc = User::with_pk(uid);
            let mut cols = ColumnsMap::new();
            cols.set_as("status", &2i8);
            let res = doc.update(db, cols, 0).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 400); // status is not updatable

            let mut cols = ColumnsMap::new();
            cols.set_as("name", &"Jarvis 1".to_string());
            let res = doc.update(db, cols, 1).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 409); // updated_at not match

            let mut cols = ColumnsMap::new();
            cols.set_as("name", &"Jarvis 1".to_string());
            let res = doc.update(db, cols, doc.updated_at).await.unwrap();
            assert!(res);

            let mut cols = ColumnsMap::new();
            cols.set_as("name", &"Jarvis 2".to_string());
            cols.set_as("birthdate", &730000i32);
            cols.set_as("locale", &Language::Zho);
            cols.set_as("picture", &"https://s.yiwen.pub/jarvis.png".to_string());
            cols.set_as("address", &"Shanghai".to_string());
            cols.set_as("website", &"https://h.yiwen.pub/jarvis".to_string());

            let mut bio: Vec<u8> = Vec::new();
            ciborium::into_writer(
                &cbor!({
                    "type" => "doc",
                    "content" => [{
                        "type" => "heading",
                        "attrs" => {
                            "id" => "Y3T1Ik",
                            "level" => 1u8,
                        },
                        "content" => [{
                            "type" => "text",
                            "text" => "Hello World 2",
                        }],
                    }],
                })
                .unwrap(),
                &mut bio,
            )
            .unwrap();
            cols.set_as("bio", &bio);
            let res = doc.update(db, cols, doc.updated_at).await.unwrap();
            assert!(res);

            doc.get_one(db, vec![]).await.unwrap();
            assert_eq!(doc.name.as_str(), "Jarvis 2");
            assert_eq!(doc.birthdate, 730000i32);
            assert_eq!(doc.locale, Language::Zho);
            assert_eq!(doc.picture.as_str(), "https://s.yiwen.pub/jarvis.png");
            assert_eq!(doc.address.as_str(), "Shanghai");
            assert_eq!(doc.website.as_str(), "https://h.yiwen.pub/jarvis");
            assert_eq!(doc.bio, bio);
        }
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn list_group_users_works() {
        let db = get_db().await;
        let gid = xid::new();

        let mut docs: Vec<User> = Vec::new();
        for i in 0..10 {
            let mut doc = User::with_pk(xid::new());
            doc.name = format!("User {}", i);
            doc.gid = gid;
            doc.save(db).await.unwrap();

            docs.push(doc)
        }
        assert_eq!(docs.len(), 10);

        let latest = User::list_group_users(db, gid, Vec::new(), 1, None, None)
            .await
            .unwrap();
        assert_eq!(latest.len(), 1);

        let mut latest = latest[0].to_owned();
        assert_eq!(latest.gid, docs.last().unwrap().gid);
        assert_eq!(latest.id, docs.last().unwrap().id);

        latest
            .update_status(db, 1, latest.updated_at)
            .await
            .unwrap();
        let res = User::list_group_users(db, gid, vec!["name".to_string()], 100, None, None)
            .await
            .unwrap();
        assert_eq!(res.len(), 10);

        let res = User::list_group_users(db, gid, vec!["name".to_string()], 100, None, Some(1))
            .await
            .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, docs.last().unwrap().id);

        let res = User::list_group_users(db, gid, vec!["name".to_string()], 5, None, None)
            .await
            .unwrap();
        assert_eq!(res.len(), 5);
        assert_eq!(res[4].id, docs[5].id);

        let res =
            User::list_group_users(db, gid, vec!["name".to_string()], 5, Some(docs[5].id), None)
                .await
                .unwrap();
        assert_eq!(res.len(), 5);
        assert_eq!(res[4].id, docs[0].id);

        let res = User::list_group_users(
            db,
            gid,
            vec!["name".to_string()],
            5,
            Some(docs[5].id),
            Some(1),
        )
        .await
        .unwrap();
        assert_eq!(res.len(), 0);
    }

    async fn batch_get_users_works() {
        let db = get_db().await;
        let gid = xid::new();

        let mut docs: Vec<User> = Vec::new();
        for i in 0..10 {
            let mut doc = User::with_pk(xid::new());
            doc.name = format!("User {}", i);
            doc.gid = gid;
            doc.save(db).await.unwrap();

            docs.push(doc)
        }
        assert_eq!(docs.len(), 10);

        let to = PackObject::Cbor(());

        let ids: Vec<PackObject<xid::Id>> = docs.iter().map(|doc| to.with(doc.id)).collect();

        let users = User::batch_get(db, ids, Vec::new()).await.unwrap();
        assert_eq!(users.len(), 10);
    }
}
