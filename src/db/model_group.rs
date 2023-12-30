use axum_web::{context::unix_ms, erring::HTTPError, object::PackObject};
use scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use crate::db::{scylladb, scylladb::extract_applied, xid_to_cn};

#[derive(Debug, Default, Clone, CqlOrm)]
pub struct GroupIndex {
    pub cn: String, // should be lowercase
    pub id: xid::Id,
    pub created_at: i64,
    pub expire_at: i64,

    pub _fields: Vec<String>, // selected fields，`_` 前缀字段会被 CqlOrm 忽略
}

impl GroupIndex {
    pub fn with_pk(cn: String) -> Self {
        Self {
            cn,
            ..Default::default()
        }
    }

    pub async fn get_one(&mut self, db: &scylladb::ScyllaDB) -> anyhow::Result<()> {
        self._fields = Self::fields();

        let query = "SELECT id,created_at,expire_at FROM group_index WHERE cn=? LIMIT 1";
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
            "INSERT INTO group_index (cn,id,created_at,expire_at) VALUES (?,?,?,?) IF NOT EXISTS";
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

        let query = "UPDATE group_index SET expire_at=? WHERE cn=? IF EXISTS";
        let params = (expire_at, &self.cn.to_lowercase());

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "Update group_index {} expire_at failed, please try again",
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
        if self.expire_at == 0 || self.expire_at + 1000 * 3600 * 24 * 365 > now {
            return Err(HTTPError::new(
                409,
                format!(
                    "Group common name {} is bundling to {}, can't reset to {}",
                    self.cn, self.id, id
                ),
            )
            .into());
        }

        self.expire_at = now + expire_at;
        let query = "UPDATE group_index SET id=?,expire_at=? WHERE cn=? IF EXISTS";
        let params = (id.to_cql(), self.expire_at, &self.cn.to_lowercase());

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "reset group {} with id {} failed, please try again",
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
pub struct Group {
    pub id: xid::Id,
    pub cn: String, // should be lowercase
    pub status: i8,
    pub kind: i8,
    pub uid: xid::Id,
    pub created_at: i64,
    pub updated_at: i64,
    pub email: String,
    pub legal_name: String,
    pub name: String,
    pub keywords: Vec<String>,
    pub logo: String,
    pub slogan: String,
    pub address: String,
    pub website: String,
    pub description: Vec<u8>,

    pub _role: i8,     // user' role in this group
    pub _priority: i8, // priority that user marked on the group
    pub _following: bool,
    pub _fields: Vec<String>, // selected fields，`_` 前缀字段会被 CqlOrm 忽略
}

impl Group {
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
        let field = "uid".to_string();
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
                    "Group status is {}, expected update to -1 or 0, got {}",
                    self.status, status
                ),
            )
            .into()),
            -1 if !(-2..=0).contains(&status) => Err(HTTPError::new(
                400,
                format!(
                    "Group status is {}, expected update to -2..=0, got {}",
                    self.status, status
                ),
            )
            .into()),
            0 if !(-1..=2).contains(&status) => Err(HTTPError::new(
                400,
                format!(
                    "Group status is {}, expected update to -1..=1, got {}",
                    self.status, status
                ),
            )
            .into()),
            1 if !(-1..=2).contains(&status) => Err(HTTPError::new(
                400,
                format!(
                    "Group status is {}, expected update to -1..=2, got {}",
                    self.status, status
                ),
            )
            .into()),
            2 if !(-1..=2).contains(&status) => Err(HTTPError::new(
                400,
                format!(
                    "Group status is {}, expected update to -1..=2, got {}",
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

        let query = format!("SELECT {} FROM group WHERE id=? LIMIT 1", fields.join(","));
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
            return Err(HTTPError::new(409, format!("Group {}, {} exists", doc.id, doc.cn)).into());
        }

        let mut i: u8 = 0;
        let expire: i64 = 1000 * 3600 * 24 * 365 * 99; // default CN expire 99 years
        loop {
            self.cn = xid_to_cn(&self.id, i);

            let mut index = GroupIndex::with_pk(self.cn.clone());
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
            "INSERT INTO group ({}) VALUES ({}) IF NOT EXISTS",
            cols_name.join(","),
            vals_name.join(",")
        );

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "Group {}, {} save failed, please try again",
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

        self.get_one(
            db,
            vec![
                "cn".to_string(),
                "uid".to_string(),
                "updated_at".to_string(),
            ],
        )
        .await?;
        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "Group {} updated_at conflict, expected updated_at {}, got {}",
                    self.id, self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.cn == cn {
            return Ok(false); // no need to update
        }

        let mut doc = GroupIndex::with_pk(cn.clone());
        doc.get_one(db).await?;
        if doc.id != self.id {
            return Err(HTTPError::new(409, format!("Group {} exists", doc.cn)).into());
        }

        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE group SET cn=?,updated_at=? WHERE id=? IF updated_at=?";
        let params = (cn.to_cql(), new_updated_at, self.id.to_cql(), updated_at);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "Group {} update_cn {} failed, please try again",
                    self.id, cn
                ),
            )
            .into());
        }

        if self.id == self.uid {
            let query = "UPDATE user SET cn=?,updated_at=? WHERE id=?";
            let params = (cn.to_cql(), new_updated_at, self.uid.to_cql());
            let _ = db.execute(query, params).await?;
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
                    "Group updated_at conflict, expected updated_at {}, got {}",
                    self.updated_at, updated_at
                ),
            )
            .into());
        }
        self.valid_status(status)?;

        if self.status == status {
            return Ok(false); // no need to update
        }

        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE group SET status=?,updated_at=? WHERE id=? IF updated_at=?";
        let params = (status, new_updated_at, self.id.to_cql(), updated_at);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!("Group update_status {} failed, please try again", status),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        self.status = status;
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
                    "Group {} updated_at conflict, expected updated_at {}, got {}",
                    self.id, self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.kind == kind {
            return Ok(false); // no need to update
        }
        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE group SET kind=?,updated_at=? WHERE id=? IF updated_at=?";
        let params = (kind, new_updated_at, self.id.to_cql(), updated_at);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "Group {} update_kind {} failed, please try again",
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
                    "Group {} updated_at conflict, expected updated_at {}, got {}",
                    self.id, self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.email == email {
            return Ok(false); // no need to update
        }
        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE group SET email=?,updated_at=? WHERE id=? IF updated_at=?";
        let params = (email.to_cql(), new_updated_at, self.id.to_cql(), updated_at);

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "Group {} update_email {} failed, please try again",
                    self.id, email
                ),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        self.email = email;
        Ok(true)
    }

    pub async fn update(
        &mut self,
        db: &scylladb::ScyllaDB,
        cols: ColumnsMap,
    ) -> anyhow::Result<bool> {
        let valid_fields = [
            "name",
            "keywords",
            "logo",
            "slogan",
            "address",
            "website",
            "description",
        ];
        let update_fields = cols.keys();
        for field in &update_fields {
            if !valid_fields.contains(&field.as_str()) {
                return Err(HTTPError::new(400, format!("Invalid field: {}", field)).into());
            }
        }

        self.get_one(db, vec!["status".to_string()]).await?;
        if self.status < 0 {
            return Err(HTTPError::new(
                409,
                format!("Group can not be update, status {}", self.status),
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
            "UPDATE group SET {} WHERE id=? IF EXISTS",
            set_fields.join(",")
        );
        params.push(self.id.to_cql());

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!("Group {} update failed, please try again", self.id),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        Ok(true)
    }

    pub async fn batch_get(
        db: &scylladb::ScyllaDB,
        ids: Vec<PackObject<xid::Id>>,
        select_fields: Vec<String>,
    ) -> anyhow::Result<Vec<Group>> {
        let fields = Self::select_fields(select_fields, false)?;

        let query = format!(
            "SELECT {} FROM group WHERE id IN ({}) USING TIMEOUT 3s",
            fields.clone().join(","),
            ids.iter().map(|_| "?").collect::<Vec<&str>>().join(",")
        );
        let params = ids
            .into_iter()
            .map(|id| id.to_cql())
            .collect::<Vec<CqlValue>>();
        let rows = db.execute_iter(query, params).await?;

        let mut res: Vec<Group> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = Group::default();
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

    use ciborium::cbor;

    use tokio::sync::OnceCell;

    use super::*;
    use crate::conf;
    use crate::db;

    static DB: OnceCell<db::scylladb::ScyllaDB> = OnceCell::const_new();

    async fn get_db() -> &'static db::scylladb::ScyllaDB {
        DB.get_or_init(|| async {
            let mut cfg = conf::Conf::new().unwrap_or_else(|err| panic!("config error: {}", err));
            cfg.scylla.keyspace = "userbase_test".to_string();
            let res = db::scylladb::ScyllaDB::new(cfg.scylla).await;
            res.unwrap()
        })
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn test_all() {
        // problem: https://users.rust-lang.org/t/tokio-runtimes-and-tokio-oncecell/91351/5
        group_index_model_works().await;
        group_model_works().await;
        batch_get_groups_works().await;
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn group_index_model_works() {
        let db = get_db().await;

        let id = xid::new();
        let mut c1 = GroupIndex {
            cn: xid_to_cn(&id, 0),
            id,
            ..Default::default()
        };
        c1.save(db, 1000 * 3600).await.unwrap();

        let id = xid::new();
        let mut c2 = GroupIndex {
            cn: xid_to_cn(&id, 0),
            id,
            ..Default::default()
        };
        c2.save(db, 1000 * 3600).await.unwrap();

        let id = xid::new();
        let mut c3 = GroupIndex {
            cn: xid_to_cn(&id, 0),
            id,
            ..Default::default()
        };
        c3.save(db, 1000 * 3600).await.unwrap();

        let mut d1 = GroupIndex::with_pk(c1.cn);
        d1.get_one(db).await.unwrap();
        assert_eq!(d1.id, c1.id);
        assert_eq!(d1.created_at + 1000 * 3600, d1.expire_at);

        let mut d2 = GroupIndex::with_pk(c2.cn);
        d2.get_one(db).await.unwrap();
        assert_eq!(d2.id, c2.id);
        assert_eq!(d2.created_at + 1000 * 3600, d2.expire_at);

        let mut d3 = GroupIndex::with_pk(c3.cn);
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

        let query = "UPDATE group_index SET expire_at=? WHERE cn=? IF EXISTS";
        let params = (unix_ms() as i64 - 1000 * 3600 * 24 * 365 - 1, &d3.cn);
        db.execute(query, params).await.unwrap();

        let res = d3.reset_cn(db, new_user, 1).await.unwrap();
        assert!(res);

        let res = d3.reset_cn(db, new_user, 1).await.unwrap();
        assert!(!res);
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn group_model_works() {
        let db = get_db().await;
        let gid = xid::new();
        let uid = xid::new();

        // valid_status
        {
            let mut doc = Group::with_pk(gid);
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

        // create
        {
            let mut doc = Group::with_pk(gid);
            doc.uid = uid;
            doc.name = "Jarvis".to_string();

            let res = doc.get_one(db, vec![]).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);

            assert!(doc.save(db).await.unwrap());
            assert_eq!(doc.cn, xid_to_cn(&doc.id, 0));

            let res = doc.save(db).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into(); // can not insert twice
            assert_eq!(err.code, 409);

            let mut doc2 = Group::with_pk(gid);
            doc2.get_one(db, vec![]).await.unwrap();
            // println!("doc: {:#?}", doc2);

            assert_eq!(doc2.name.as_str(), "Jarvis");
            assert_eq!(doc2.id, doc.id);
            assert_eq!(doc2.cn, doc.cn);

            let mut doc3 = Group::with_pk(gid);
            doc3.get_one(db, vec!["name".to_string()]).await.unwrap();
            assert_eq!(doc3.name.as_str(), "Jarvis");
            assert_eq!(doc3.id, doc.id);
            assert_eq!(doc3.cn, doc.cn);
            assert_eq!(doc3._fields, vec!["name", "cn", "uid"]);
        }

        // // update_cn
        // {
        //     let mut doc = Group::with_pk(uid);
        //     doc.get_one(db, vec![]).await.unwrap();

        //     let cn = doc.cn.clone() + "jarvis";

        //     let res = doc
        //         .update_cn(db, "Jarvis".to_string(), doc.updated_at)
        //         .await;
        //     assert!(res.is_err());
        //     let err: erring::HTTPError = res.unwrap_err().into();
        //     assert_eq!(err.code, 400);

        //     let res = doc.update_cn(db, cn.clone(), doc.updated_at - 1).await;
        //     assert!(res.is_err());
        //     let err: erring::HTTPError = res.unwrap_err().into();
        //     assert_eq!(err.code, 409);

        //     let res = doc
        //         .update_cn(db, doc.cn.clone(), doc.updated_at)
        //         .await
        //         .unwrap();
        //     assert!(!res);

        //     let res = doc
        //         .update_cn(db, "jarvis".to_string(), doc.updated_at - 1)
        //         .await;
        //     assert!(res.is_err());
        //     let err: erring::HTTPError = res.unwrap_err().into();
        //     assert_eq!(err.code, 409);

        //     let res = doc.update_cn(db, cn.clone(), doc.updated_at).await;
        //     assert!(res.is_err());
        //     let err: erring::HTTPError = res.unwrap_err().into();
        //     assert_eq!(err.code, 404);

        //     let mut index = GroupIndex {
        //         cn: cn.clone(),
        //         id: uid,
        //         ..Default::default()
        //     };
        //     index.save(db, 1000 * 3600).await.unwrap();
        //     let res = doc.update_cn(db, cn.clone(), doc.updated_at).await.unwrap();
        //     assert!(res);
        // }

        // update status
        {
            let mut doc = Group::with_pk(gid);
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

        // update kind
        {
            let mut doc = Group::with_pk(gid);
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
            let mut doc = Group::with_pk(gid);
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

        // update
        {
            let mut doc = Group::with_pk(gid);
            let mut cols = ColumnsMap::new();
            cols.set_as("status", &2i8);
            let res = doc.update(db, cols).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 400); // status is not updatable

            let mut cols = ColumnsMap::new();
            cols.set_as("name", &"Jarvis 1".to_string());
            let res = doc.update(db, cols).await.unwrap();
            assert!(res);

            let mut cols = ColumnsMap::new();
            cols.set_as("name", &"Jarvis 2".to_string());
            cols.set_as("keywords", &vec!["test".to_string()]);
            cols.set_as("logo", &"https://s.yiwen.pub/jarvis.png".to_string());
            cols.set_as(
                "slogan",
                &"Translating Knowledge into the Future".to_string(),
            );
            cols.set_as("address", &"Shanghai".to_string());
            cols.set_as("website", &"https://h.yiwen.pub/jarvis".to_string());

            let mut description: Vec<u8> = Vec::new();
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
                &mut description,
            )
            .unwrap();
            cols.set_as("description", &description);
            let res = doc.update(db, cols).await.unwrap();
            assert!(res);

            doc.get_one(db, vec![]).await.unwrap();
            assert_eq!(doc.name.as_str(), "Jarvis 2");
            assert_eq!(doc.keywords, vec!["test".to_string()]);
            assert_eq!(doc.logo.as_str(), "https://s.yiwen.pub/jarvis.png");
            assert_eq!(doc.slogan.as_str(), "Translating Knowledge into the Future");
            assert_eq!(doc.address.as_str(), "Shanghai");
            assert_eq!(doc.website.as_str(), "https://h.yiwen.pub/jarvis");
            assert_eq!(doc.description, description);
        }
    }

    async fn batch_get_groups_works() {
        let db = get_db().await;
        let uid = xid::new();

        let mut docs: Vec<Group> = Vec::new();
        for i in 0..10 {
            let mut doc = Group::with_pk(xid::new());
            doc.name = format!("group {}", i);
            doc.uid = uid;
            doc.save(db).await.unwrap();

            docs.push(doc)
        }
        assert_eq!(docs.len(), 10);

        let to = PackObject::Cbor(());

        let ids: Vec<PackObject<xid::Id>> = docs.iter().map(|doc| to.with(doc.id)).collect();

        let groups = Group::batch_get(db, ids, Vec::new()).await.unwrap();
        assert_eq!(groups.len(), 10);
    }
}
