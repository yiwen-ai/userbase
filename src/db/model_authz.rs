use std::collections::HashSet;

use axum_web::context::unix_ms;
use axum_web::erring::HTTPError;
use scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use crate::db::{
    scylladb,
    scylladb::{extract_applied, Query},
};

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct AuthZ {
    pub aud: xid::Id,
    pub sub: uuid::Uuid,
    pub uid: xid::Id,
    pub created_at: i64,
    pub updated_at: i64,
    pub expire_at: i64,
    pub scope: HashSet<String>,
    pub ip: String,

    pub _fields: Vec<String>, // selected fields，`_` 前缀字段会被 CqlOrm 忽略
}

impl AuthZ {
    pub fn with_pk(aud: xid::Id, sub: uuid::Uuid) -> Self {
        Self {
            aud,
            sub,
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
            let field = "aud".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            let field = "sub".to_string();
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
            "SELECT {} FROM authz WHERE aud=? AND sub=? LIMIT 1",
            fields.join(",")
        );
        let params = (self.aud.to_cql(), self.sub.to_cql());
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
                    "AuthZ {}, {} save failed, please try again",
                    self.aud, self.sub,
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
                    self.sub, self.aud, self.uid, uid
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
            "UPDATE authz SET {} WHERE aud=? AND sub=? IF EXISTS",
            set_fields.join(",")
        );

        params.push(self.aud.to_cql());
        params.push(self.sub.to_cql());
        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthZ {}, {} update failed, please try again",
                    self.aud, self.sub
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
                    "AuthZ {}, {} delete conflict, expected uid {}, got {}",
                    self.aud, self.sub, self.uid, uid
                ),
            )
            .into());
        }

        let query = "DELETE FROM authz WHERE aud=? AND sub=? IF uid=?";
        let params = (self.aud.to_cql(), self.sub.to_cql(), uid.to_cql());
        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthZ {}, {} delete failed, please try again",
                    self.aud, self.sub
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

        res.sort_by(|a, b| b.updated_at.partial_cmp(&a.updated_at).unwrap());
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use axum_web::erring;

    
    use tokio::{sync::OnceCell, time};

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
    async fn test_all() -> anyhow::Result<()> {
        // problem: https://users.rust-lang.org/t/tokio-runtimes-and-tokio-oncecell/91351/5
        authz_model_works().await?;
        list_by_uid_works().await?;

        Ok(())
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn authz_model_works() -> anyhow::Result<()> {
        let db = get_db().await;
        let uid = xid::new();
        let aud = xid::new();
        let sub = uuid::Uuid::new_v4();

        // create
        {
            let mut doc = AuthZ::with_pk(aud, sub);
            doc.uid = uid;
            doc.expire_at = (unix_ms() + 3600 * 1000) as i64;

            let res = doc.get_one(db, vec![]).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);

            assert!(doc.save(db).await?);

            let res = doc.save(db).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into(); // can not insert twice
            assert_eq!(err.code, 409);

            let mut doc2 = AuthZ::with_pk(aud, sub);
            doc2.get_one(db, vec![]).await?;
            assert_eq!(doc2.uid, uid);

            let mut doc3 = AuthZ::with_pk(aud, sub);
            doc3.get_one(db, vec!["scope".to_string()]).await?;

            assert_eq!(doc3.uid, uid);
            assert_eq!(doc3._fields, vec!["scope", "uid"]);
        }

        // update
        {
            let mut doc = AuthZ::with_pk(aud, sub);
            let mut cols = ColumnsMap::new();
            cols.set_as("status", &2i8);
            let res = doc.update(db, cols, uid).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 400); // status is not updatable

            let mut cols = ColumnsMap::new();
            cols.set_as("ip", &"1.2.3.4".to_string());
            let res = doc.update(db, cols, xid::new()).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 409); // uid not match

            let mut cols = ColumnsMap::new();
            cols.set_as("ip", &"1.2.3.4".to_string());
            let res = doc.update(db, cols, uid).await?;
            assert!(res);

            let expire_at = (unix_ms() + 3610 * 1000) as i64;
            let mut cols = ColumnsMap::new();
            cols.set_as("ip", &"1.2.3.4".to_string());
            cols.set_as("scope", &HashSet::from(["read".to_string()]));
            cols.set_as("expire_at", &expire_at);

            let updated_at = doc.updated_at;
            time::sleep(time::Duration::from_millis(10)).await;
            let res = doc.update(db, cols, uid).await?;
            assert!(res);

            let mut doc2 = AuthZ::with_pk(aud, sub);
            doc2.get_one(db, vec![]).await?;
            assert_eq!(doc2.expire_at, expire_at);
            assert_eq!(doc2.scope, HashSet::from(["read".to_string()]));
            assert_eq!(doc2.ip.as_str(), "1.2.3.4");
            assert!(doc2.updated_at > updated_at);
        }

        // delete
        {
            let mut doc = AuthZ::with_pk(aud, sub);
            let res = doc.delete(db, xid::new()).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 409);

            let res = doc.delete(db, doc.uid).await?;
            assert!(res);

            let res = doc.delete(db, doc.uid).await?;
            assert!(!res);
        }

        Ok(())
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn list_by_uid_works() -> anyhow::Result<()> {
        let db = get_db().await;
        let uid = xid::new();
        let _aud = xid::new();
        let sub = uuid::Uuid::new_v4();

        let mut docs: Vec<AuthZ> = Vec::new();
        for _i in 0..10 {
            let mut doc = AuthZ::with_pk(xid::new(), sub);
            doc.uid = uid;
            doc.save(db).await?;
            docs.push(doc)
        }

        assert_eq!(docs.len(), 10);

        let res = AuthZ::list_by_uid(db, uid, Vec::new()).await?;
        assert_eq!(res.len(), 10);
        assert_eq!(res[0].aud, docs[9].aud);
        assert_eq!(res[9].aud, docs[0].aud);
        Ok(())
    }
}
