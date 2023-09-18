use axum_web::context::unix_ms;
use axum_web::erring::HTTPError;
use scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use crate::db::{scylladb, scylladb::extract_applied};

use super::Group;

#[derive(Debug, Default, Clone, CqlOrm)]
pub struct Follow {
    pub uid: xid::Id,
    pub gid: xid::Id,
    pub created_at: i64,

    pub _fields: Vec<String>, // selected fields，`_` 前缀字段会被 CqlOrm 忽略
}

impl Follow {
    pub fn with_pk(uid: xid::Id, gid: xid::Id) -> Self {
        Self {
            uid,
            gid,
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
            let field = "uid".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            let field = "gid".to_string();
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
            "SELECT {} FROM follow WHERE uid=? AND gid=? LIMIT 1",
            fields.join(",")
        );
        let params = (self.uid.to_cql(), self.gid.to_cql());
        let res = db.execute(query, params).await?.single_row()?;

        let mut cols = ColumnsMap::with_capacity(fields.len());
        cols.fill(res, &fields)?;
        self.fill(&cols);

        Ok(())
    }

    pub async fn save(&mut self, db: &scylladb::ScyllaDB) -> anyhow::Result<bool> {
        let now = unix_ms() as i64;
        self.created_at = now;

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
            "INSERT INTO follow ({}) VALUES ({}) IF NOT EXISTS",
            cols_name.join(","),
            vals_name.join(",")
        );

        let res = db.execute(query, params).await?;
        Ok(extract_applied(res))
    }

    pub async fn delete(&mut self, db: &scylladb::ScyllaDB) -> anyhow::Result<bool> {
        let res = self.get_one(db, vec!["created_at".to_string()]).await;
        if res.is_err() {
            return Ok(false); // already deleted
        }

        let query = "DELETE FROM follow WHERE uid=? AND gid=?";
        let params = (self.uid.to_cql(), self.gid.to_cql());
        let _ = db.execute(query, params).await?;

        Ok(true)
    }

    pub async fn all_gids(db: &scylladb::ScyllaDB, uid: xid::Id) -> anyhow::Result<Vec<xid::Id>> {
        let query = "SELECT gid FROM follow WHERE uid=? LIMIT ? USING TIMEOUT 3s";
        let params = (uid.to_cql(), 1000i32);
        let rows = db.execute_iter(query, params).await?;

        let mut gids: Vec<xid::Id> = Vec::with_capacity(rows.len());
        let follow_fields = vec!["gid".to_string()];
        for row in rows {
            let mut doc = Follow::default();
            let mut cols = ColumnsMap::with_capacity(follow_fields.len());
            cols.fill(row, &follow_fields)?;
            doc.fill(&cols);
            gids.push(doc.gid);
        }

        Ok(gids)
    }

    pub async fn list_groups(
        db: &scylladb::ScyllaDB,
        uid: xid::Id,
        select_fields: Vec<String>,
        page_size: u16,
        page_token: Option<xid::Id>,
    ) -> anyhow::Result<Vec<Group>> {
        let follow_fields = Self::fields();
        let query = format!(
            "SELECT {} FROM follow WHERE uid=? LIMIT ? USING TIMEOUT 3s",
            follow_fields.clone().join(",")
        );
        let params = (uid.to_cql(), 1000i32);
        let rows = db.execute_iter(query, params).await?;

        let mut follows: Vec<Follow> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = Follow::default();
            let mut cols = ColumnsMap::with_capacity(follow_fields.len());
            cols.fill(row, &follow_fields)?;
            doc.fill(&cols);
            doc._fields = follow_fields.clone();
            follows.push(doc);
        }

        follows.sort_by(|a, b| b.created_at.partial_cmp(&a.created_at).unwrap());
        if !follows.is_empty() {
            if let Some(gid) = page_token {
                if follows.last().unwrap().gid >= gid {
                    follows.truncate(0);
                } else if follows.first().unwrap().gid >= gid {
                    let mut iter = follows.split_inclusive(|follow| follow.gid == gid).skip(1);
                    if let Some(rt) = iter.next() {
                        if !rt.is_empty() {
                            follows = rt.to_vec();
                        }
                    }
                }
            }
        }

        if follows.len() > page_size as usize {
            follows.truncate(page_size as usize);
        }

        let mut res: Vec<Group> = Vec::with_capacity(follows.len());
        let fields = Group::select_fields(select_fields, true)?;
        for m in follows {
            let mut doc = Group::with_pk(m.gid);
            doc.get_one(db, fields.clone()).await?;
            doc._fields = fields.clone();
            res.push(doc);
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use axum_web::erring;

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
        follow_model_works().await;
        list_groups_works().await;
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn follow_model_works() {
        let db = get_db().await;
        let uid = xid::new();
        let gid = xid::new();

        // create
        {
            let mut doc = Follow::with_pk(uid, gid);

            let res = doc.get_one(db, vec![]).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);

            assert!(doc.save(db).await.unwrap());
            let created_at = doc.created_at;

            let res = doc.save(db).await.unwrap();
            assert!(!res);

            let mut doc2 = Follow::with_pk(uid, gid);
            doc2.get_one(db, vec![]).await.unwrap();
            // println!("doc: {:#?}", doc2);

            assert_eq!(doc2.created_at, created_at);

            let mut doc3 = Follow::with_pk(uid, gid);
            doc3.get_one(db, vec!["created_at".to_string()])
                .await
                .unwrap();
            assert_eq!(doc3.created_at, created_at);
            assert_eq!(doc3._fields, vec!["created_at"]);
        }

        // delete
        {
            let mut doc = Follow::with_pk(uid, gid);
            doc.get_one(db, vec![]).await.unwrap();

            let res = doc.delete(db).await.unwrap();
            assert!(res);

            let res = doc.delete(db).await.unwrap();
            assert!(!res);
        }
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn list_groups_works() {
        let db = get_db().await;
        let uid = xid::new();

        let mut docs: Vec<Follow> = Vec::new();
        for i in 0..10 {
            let mut group = Group::with_pk(xid::new());
            group.uid = xid::new();
            group.name = format!("Group {}", i);
            group.save(db).await.unwrap();

            let mut doc = Follow::with_pk(uid, group.id);
            doc.save(db).await.unwrap();
            docs.push(doc)
        }

        assert_eq!(docs.len(), 10);

        let gids = Follow::all_gids(db, uid).await.unwrap();
        assert_eq!(gids.len(), 10);
        println!("gids: {:?}", gids);

        let latest = Follow::list_groups(db, uid, Vec::new(), 1, None)
            .await
            .unwrap();
        assert_eq!(latest.len(), 1);

        let latest = latest[0].to_owned();
        assert_eq!(latest.id, docs.last().unwrap().gid);

        let res = Follow::list_groups(db, uid, vec![], 100, None)
            .await
            .unwrap();
        assert_eq!(res.len(), 10);

        let res = Follow::list_groups(db, uid, vec![], 5, None).await.unwrap();
        assert_eq!(res.len(), 5);
        assert_eq!(res[4].id, docs[5].gid);

        let res = Follow::list_groups(db, uid, vec![], 5, Some(docs[5].gid))
            .await
            .unwrap();
        assert_eq!(res.len(), 5);
        assert_eq!(res[4].id, docs[0].gid);
    }
}
