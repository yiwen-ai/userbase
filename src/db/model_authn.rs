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
pub struct AuthN {
    pub idp: String,
    pub aud: String,
    pub sub: String,
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
    pub fn with_pk(idp: String, aud: String, sub: String) -> Self {
        Self {
            idp,
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
            let field = "idp".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
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
            "SELECT {} FROM authn WHERE idp=? AND aud=? AND sub=? LIMIT 1",
            fields.join(",")
        );
        let params = (&self.idp, &self.aud, &self.sub);
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
                    self.idp, self.aud, self.sub, self.uid
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
            "UPDATE authn SET {} WHERE idp=? AND aud=? AND sub=? IF uid=?",
            set_fields.join(",")
        );
        params.push(self.idp.to_cql());
        params.push(self.aud.to_cql());
        params.push(self.sub.to_cql());
        params.push(uid.to_cql());

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthN {}, {}, {} update failed, please try again",
                    self.idp, self.aud, self.sub
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
                    self.idp, self.aud, self.sub, self.uid, uid
                ),
            )
            .into());
        }

        let query = "DELETE FROM authn WHERE idp=? AND aud=? AND sub=? IF uid=?";
        let params = (
            self.idp.to_cql(),
            self.aud.to_cql(),
            self.sub.to_cql(),
            uid.to_cql(),
        );
        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "AuthN {}, {}, {} delete failed, please try again",
                    self.idp, self.aud, self.sub
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

        res.sort_by(|a, b| b.updated_at.partial_cmp(&a.updated_at).unwrap());

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use axum_web::erring;

    use ciborium::cbor;
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
    async fn test_all() {
        // problem: https://users.rust-lang.org/t/tokio-runtimes-and-tokio-oncecell/91351/5
        authn_model_works().await;
        list_by_uid_works().await;
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn authn_model_works() {
        let db = get_db().await;
        let uid = xid::new();
        let idp = "github".to_string();
        let aud = xid::new().to_string();
        let sub = "jarvis".to_string();

        // create
        {
            let mut doc = AuthN::with_pk(idp.clone(), aud.clone(), sub.clone());
            doc.uid = uid;
            doc.expire_at = (unix_ms() + 3600 * 1000) as i64;

            let res = doc.get_one(db, vec![]).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);

            assert!(doc.save(db).await.unwrap());

            let res = doc.save(db).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into(); // can not insert twice
            assert_eq!(err.code, 409);

            let mut doc2 = AuthN::with_pk(idp.clone(), aud.clone(), sub.clone());
            doc2.get_one(db, vec![]).await.unwrap();
            assert_eq!(doc2.uid, uid);

            let mut doc3 = AuthN::with_pk(idp.clone(), aud.clone(), sub.clone());
            doc3.get_one(db, vec!["scope".to_string()]).await.unwrap();

            assert_eq!(doc3.uid, uid);
            assert_eq!(doc3._fields, vec!["scope", "uid"]);
        }

        // update
        {
            let mut doc = AuthN::with_pk(idp.clone(), aud.clone(), sub.clone());
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
            let res = doc.update(db, cols, uid).await.unwrap();
            assert!(res);

            let expire_at = (unix_ms() + 3610 * 1000) as i64;
            let mut cols = ColumnsMap::new();
            cols.set_as("ip", &"1.2.3.4".to_string());
            cols.set_as("scope", &HashSet::from(["read".to_string()]));
            cols.set_as("expire_at", &expire_at);

            let mut payload: Vec<u8> = Vec::new();
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
                &mut payload,
            )
            .unwrap();
            cols.set_as("payload", &payload);
            let updated_at = doc.updated_at;
            time::sleep(time::Duration::from_millis(10)).await;
            let res = doc.update(db, cols, uid).await.unwrap();
            assert!(res);

            let mut doc2 = AuthN::with_pk(idp.clone(), aud.clone(), sub.clone());
            doc2.get_one(db, vec![]).await.unwrap();
            assert_eq!(doc2.expire_at, expire_at);
            assert_eq!(doc2.scope, HashSet::from(["read".to_string()]));
            assert_eq!(doc2.ip.as_str(), "1.2.3.4");
            assert_eq!(doc2.payload, payload);
            assert!(doc2.updated_at > updated_at);
        }

        // delete
        {
            let mut doc = AuthN::with_pk(idp.clone(), aud.clone(), sub.clone());
            let res = doc.delete(db, xid::new()).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 409);

            let res = doc.delete(db, doc.uid).await.unwrap();
            assert!(res);

            let res = doc.delete(db, doc.uid).await.unwrap();
            assert!(!res);
        }
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn list_by_uid_works() {
        let db = get_db().await;
        let uid = xid::new();
        let idp = "github".to_string();
        let aud = xid::new().to_string();
        let sub = "jarvis".to_string();

        let mut docs: Vec<AuthN> = Vec::new();
        for i in 0..10 {
            let mut doc = AuthN::with_pk(idp.clone(), format!("{}-{}", aud, i), sub.clone());
            doc.uid = uid;
            doc.save(db).await.unwrap();
            docs.push(doc)
        }

        assert_eq!(docs.len(), 10);

        let res = AuthN::list_by_uid(db, uid, Vec::new()).await.unwrap();
        assert_eq!(res.len(), 10);
        assert_eq!(res[0].aud, docs[9].aud);
        assert_eq!(res[9].aud, docs[0].aud);
    }
}
