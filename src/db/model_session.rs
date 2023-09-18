use axum_web::context::unix_ms;
use axum_web::erring::HTTPError;
use scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use crate::db::{scylladb, scylladb::extract_applied};

const SESSION_TTL_DEFAULT: i32 = 3600 * 24 * 30; // 30 days
const SESSION_TTL_MIN: i32 = 1;
const SESSION_TTL_MAX: i32 = 3600 * 24 * 400; // 400 days

#[derive(Debug, Default, Clone, CqlOrm, PartialEq)]
pub struct Session {
    pub id: xid::Id,
    pub uid: xid::Id,
    pub created_at: i64,
    pub updated_at: i64,
    pub ttl: i32,
    pub device_id: String,
    pub device_desc: String,
    pub idp: String,
    pub aud: String,
    pub sub: String,

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
            "INSERT INTO session ({}) VALUES ({}) IF NOT EXISTS USING TTL ?",
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

        let mut fields = self._fields.clone();
        if let Some(i) = fields.iter().position(|n| n == "id") {
            fields.remove(i);
        }

        let mut set_fields: Vec<String> = Vec::with_capacity(fields.len());
        let mut params: Vec<CqlValue> = Vec::with_capacity(fields.len() + 2);
        let cols = self.to();

        params.push(self.ttl.to_cql());
        for field in &fields {
            set_fields.push(format!("{}=?", field));
            params.push(cols.get(field).unwrap().to_owned());
        }

        let query = format!(
            "UPDATE session USING TTL ? SET {} WHERE id=? IF EXISTS",
            set_fields.join(",")
        );

        params.push(self.id.to_cql());
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

        let query = format!(
            "SELECT {} FROM session WHERE uid=? LIMIT 1000 USING TIMEOUT 3s",
            fields.clone().join(",")
        );
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

        res.sort_by(|a, b| a.id.partial_cmp(&b.id).unwrap());
        Ok(res)
    }

    pub async fn find_by_authn(
        db: &scylladb::ScyllaDB,
        uid: xid::Id,
        device_id: &str,
        idp: &str,
        aud: &str,
        sub: &str,
    ) -> anyhow::Result<Session> {
        let fields = Self::select_fields(vec![], true)?;

        // 正常情况下应该只有 0～1 条数据
        let query = format!(
            "SELECT {} FROM session WHERE uid=? AND device_id=? AND idp=? AND aud=? AND sub=? LIMIT 2 ALLOW FILTERING USING TIMEOUT 3s",
            fields.clone().join(",")
        );
        let params = (uid.to_cql(), device_id, idp, aud, sub);
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

        res.sort_by(|a, b| b.id.partial_cmp(&a.id).unwrap());
        if res.is_empty() {
            return Err(
                HTTPError::new(404, format!("session {}, {} not found", uid, device_id)).into(),
            );
        }

        Ok(res[0].to_owned())
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
    async fn test_all() {
        // problem: https://users.rust-lang.org/t/tokio-runtimes-and-tokio-oncecell/91351/5
        session_model_works().await;
        list_by_uid_works().await;
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn session_model_works() {
        let db = get_db().await;
        let uid = xid::new();
        let sid = xid::new();

        // create
        {
            let mut doc = Session::with_pk(sid);
            doc.uid = uid;

            let res = doc.get_one(db, vec![]).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);

            assert!(doc.save(db, 1).await.unwrap());

            let res = doc.save(db, 1).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into(); // can not insert twice
            assert_eq!(err.code, 409);

            let mut doc2 = Session::with_pk(sid);
            doc2.get_one(db, vec![]).await.unwrap();
            assert_eq!(doc2.uid, doc.uid);

            let mut doc3 = Session::with_pk(sid);
            doc3.get_one(db, vec!["ttl".to_string()]).await.unwrap();

            assert_eq!(doc3.ttl, 1i32);
            assert_eq!(doc3._fields, vec!["ttl"]);

            time::sleep(time::Duration::from_millis(1100)).await;
            let mut doc3 = Session::with_pk(sid);
            let res = doc3.get_one(db, vec!["ttl".to_string()]).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);
        }

        // renew
        {
            let mut doc = Session::with_pk(sid);
            doc.uid = uid;
            doc.ttl = 1;

            let res = doc.renew(db).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);

            assert!(doc.save(db, 3).await.unwrap());
            time::sleep(time::Duration::from_millis(1500)).await;

            let mut doc2 = Session::with_pk(sid);
            assert!(doc2.renew(db).await.unwrap());
            assert_eq!(doc2.ttl, 3);
            assert_eq!(doc2.uid, uid);
            assert!(doc2.created_at > doc.created_at);

            time::sleep(time::Duration::from_millis(2000)).await;
            let mut doc3 = Session::with_pk(sid);
            doc3.get_one(db, vec!["ttl".to_string()]).await.unwrap();

            time::sleep(time::Duration::from_millis(1100)).await;
            let mut doc3 = Session::with_pk(sid);
            let res = doc3.get_one(db, vec!["ttl".to_string()]).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);
        }

        // delete
        {
            let mut doc = Session::with_pk(sid);
            let res = doc.delete(db, xid::new()).await.unwrap();
            assert!(!res);

            doc.uid = uid;
            assert!(doc.save(db, 99).await.unwrap());

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

        let mut docs: Vec<Session> = Vec::new();
        for _i in 0..10 {
            let mut doc = Session::with_pk(xid::new());
            doc.uid = uid;
            doc.save(db, 99).await.unwrap();
            docs.push(doc)
        }

        assert_eq!(docs.len(), 10);

        let res = Session::list_by_uid(db, uid, Vec::new()).await.unwrap();
        assert_eq!(res.len(), 10);
        assert_eq!(res[0].id, docs[0].id);
        assert_eq!(res[9].id, docs[9].id);
    }
}
