use axum_web::context::unix_ms;
use axum_web::erring::HTTPError;
use scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use crate::db::{
    scylladb,
    scylladb::{extract_applied, Query},
};

use super::Group;

#[derive(Debug, Default, Clone, CqlOrm)]
pub struct Member {
    pub gid: xid::Id,
    pub uid: xid::Id,
    pub role: i8,
    pub priority: i8,
    pub created_at: i64,
    pub updated_at: i64,

    pub _fields: Vec<String>, // selected fields，`_` 前缀字段会被 CqlOrm 忽略
}

impl Member {
    pub fn with_pk(gid: xid::Id, uid: xid::Id) -> Self {
        Self {
            gid,
            uid,
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
            let field = "gid".to_string();
            if !select_fields.contains(&field) {
                select_fields.push(field);
            }
            let field = "uid".to_string();
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
            "SELECT {} FROM member WHERE gid=? AND uid=? LIMIT 1",
            fields.join(",")
        );
        let params = (self.gid.to_cql(), self.uid.to_cql());
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
            "INSERT INTO member ({}) VALUES ({}) IF NOT EXISTS",
            cols_name.join(","),
            vals_name.join(",")
        );

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(
                HTTPError::new(409, format!("{}, {} already exists", self.gid, self.uid)).into(),
            );
        }

        Ok(true)
    }

    pub async fn update_role(
        &mut self,
        db: &scylladb::ScyllaDB,
        role: i8,
        updated_at: i64,
    ) -> anyhow::Result<bool> {
        if !(-2..=2).contains(&role) {
            return Err(HTTPError::new(400, format!("Invalid role: {}", role)).into());
        }

        self.get_one(db, vec!["role".to_string(), "updated_at".to_string()])
            .await?;
        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "Member updated_at conflict, expected updated_at {}, got {}",
                    self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.role == role {
            return Ok(false); // no need to update
        }
        let new_updated_at = unix_ms() as i64;
        let query = "UPDATE member SET role=?,updated_at=? WHERE gid=? AND uid=? IF updated_at=?";
        let params = (
            role,
            new_updated_at,
            self.gid.to_cql(),
            self.uid.to_cql(),
            updated_at,
        );

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!("Member update_role {} failed, please try again", role),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        self.role = role;
        Ok(true)
    }

    pub async fn update_priority(
        &mut self,
        db: &scylladb::ScyllaDB,
        priority: i8,
        updated_at: i64,
    ) -> anyhow::Result<bool> {
        if !(-1..=2).contains(&priority) {
            return Err(HTTPError::new(400, format!("Invalid priority: {}", priority)).into());
        }

        self.get_one(db, vec!["priority".to_string(), "updated_at".to_string()])
            .await?;
        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "Member updated_at conflict, expected updated_at {}, got {}",
                    self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.priority == priority {
            return Ok(false); // no need to update
        }
        let new_updated_at = unix_ms() as i64;
        let query =
            "UPDATE member SET priority=?,updated_at=? WHERE gid=? AND uid=? IF updated_at=?";
        let params = (
            priority,
            new_updated_at,
            self.gid.to_cql(),
            self.uid.to_cql(),
            updated_at,
        );

        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "Member update_priority {} failed, please try again",
                    priority
                ),
            )
            .into());
        }

        self.updated_at = new_updated_at;
        self.priority = priority;
        Ok(true)
    }

    pub async fn delete(
        &mut self,
        db: &scylladb::ScyllaDB,
        updated_at: i64,
    ) -> anyhow::Result<bool> {
        let res = self
            .get_one(db, vec!["role".to_string(), "updated_at".to_string()])
            .await;
        if res.is_err() {
            return Ok(false); // already deleted
        }

        if self.updated_at != updated_at {
            return Err(HTTPError::new(
                409,
                format!(
                    "Member updated_at conflict, expected version {}, got {}",
                    self.updated_at, updated_at
                ),
            )
            .into());
        }

        if self.role != -2 {
            return Err(HTTPError::new(
                409,
                format!(
                    "Member {}, {} is not disabled, can't delete",
                    self.gid, self.uid
                ),
            )
            .into());
        }

        let query = "DELETE FROM member WHERE gid=? AND uid=? IF updated_at=?";
        let params = (self.gid.to_cql(), self.uid.to_cql(), updated_at);
        let res = db.execute(query, params).await?;
        if !extract_applied(res) {
            return Err(HTTPError::new(
                409,
                format!(
                    "Member {}, {} delete failed, please try again",
                    self.gid, self.uid
                ),
            )
            .into());
        }

        Ok(true)
    }

    pub async fn list_members(
        db: &scylladb::ScyllaDB,
        gid: xid::Id,
        select_fields: Vec<String>,
        page_size: u16,
        page_token: Option<xid::Id>,
        role: Option<i8>,
    ) -> anyhow::Result<Vec<Member>> {
        let mut fields = Self::select_fields(select_fields, true)?;
        // status field is a personal info, so we need to remove it
        if let Some(i) = fields.iter().position(|n| n == "status") {
            fields.remove(i);
        }

        let rows = if let Some(uid) = page_token {
            if role.is_none() {
                let query = Query::new(format!(
                "SELECT {} FROM member WHERE gid=? AND uid>? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                fields.clone().join(",")))
                .with_page_size(page_size as i32);
                let params = (gid.to_cql(), uid.to_cql(), page_size as i32);
                db.execute_paged(query, params, None).await?
            } else {
                let query = Query::new(format!(
                    "SELECT {} FROM member WHERE gid=? AND uid>? AND role=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                    fields.clone().join(","))).with_page_size(page_size as i32);
                let params = (gid.to_cql(), uid.to_cql(), role.unwrap(), page_size as i32);
                db.execute_paged(query, params, None).await?
            }
        } else if role.is_none() {
            let query = Query::new(format!(
                "SELECT {} FROM member WHERE gid=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                fields.clone().join(",")
            ))
            .with_page_size(page_size as i32);
            let params = (gid.to_cql(), page_size as i32);
            db.execute_iter(query, params).await?
        } else {
            let query = Query::new(format!(
                "SELECT {} FROM member WHERE gid=? AND role=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                fields.clone().join(",")
            )).with_page_size(page_size as i32);
            let params = (gid.as_bytes(), role.unwrap(), page_size as i32);
            db.execute_iter(query, params).await?
        };

        let mut res: Vec<Member> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = Member::default();
            let mut cols = ColumnsMap::with_capacity(fields.len());
            cols.fill(row, &fields)?;
            doc.fill(&cols);
            doc._fields = fields.clone();
            res.push(doc);
        }

        Ok(res)
    }

    pub async fn list_groups(
        db: &scylladb::ScyllaDB,
        uid: xid::Id,
        select_fields: Vec<String>,
        page_size: u16,
        page_token: Option<xid::Id>,
        priority: Option<i8>,
    ) -> anyhow::Result<Vec<Group>> {
        let member_fields = vec![
            "gid".to_string(),
            "role".to_string(),
            "priority".to_string(),
            "created_at".to_string(),
        ];
        let rows = if priority.is_none() {
            let query = Query::new(format!(
                "SELECT {} FROM member WHERE uid=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                member_fields.clone().join(",")
            ))
            .with_page_size(1000i32);
            let params = (uid.to_cql(), 1000i32);
            db.execute_paged(query, params, None).await?
        } else {
            let query = Query::new(format!(
                    "SELECT {} FROM member WHERE uid=? AND priority=? LIMIT ? ALLOW FILTERING BYPASS CACHE USING TIMEOUT 3s",
                    member_fields.clone().join(","))).with_page_size(1000i32);
            let params = (uid.to_cql(), priority.unwrap(), 1000i32);
            db.execute_paged(query, params, None).await?
        };

        let mut members: Vec<Member> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut doc = Member::default();
            let mut cols = ColumnsMap::with_capacity(member_fields.len());
            cols.fill(row, &member_fields)?;
            doc.fill(&cols);
            doc._fields = member_fields.clone();
            members.push(doc);
        }

        members.sort_by(|a, b| b.created_at.partial_cmp(&a.created_at).unwrap());
        if !members.is_empty() {
            if let Some(gid) = page_token {
                if members.last().unwrap().gid >= gid {
                    members.truncate(0);
                } else if members.first().unwrap().gid >= gid {
                    let mut iter = members.split_inclusive(|member| member.gid == gid).skip(1);
                    if let Some(rt) = iter.next() {
                        if !rt.is_empty() {
                            members = rt.to_vec();
                        }
                    }
                }
            }
        }

        if members.len() > page_size as usize {
            members.truncate(page_size as usize);
        }

        let mut res: Vec<Group> = Vec::with_capacity(members.len());
        let mut fields = Group::select_fields(select_fields, true)?;
        fields.push("_role".to_string());
        fields.push("_priority".to_string());
        for m in members {
            let mut doc = Group::with_pk(m.gid);
            doc.get_one(db, fields.clone()).await?;
            doc._role = m.role;
            doc._priority = m.priority;
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
        member_model_works().await;
        list_members_works().await;
        list_groups_works().await;
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn member_model_works() {
        let db = get_db().await;
        let uid = xid::new();
        let gid = xid::new();

        // create
        {
            let mut doc = Member::with_pk(gid, uid);
            doc.role = 2;

            let res = doc.get_one(db, vec![]).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 404);

            assert!(doc.save(db).await.unwrap());

            let res = doc.save(db).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into(); // can not insert twice
            assert_eq!(err.code, 409);

            let mut doc2 = Member::with_pk(gid, uid);
            doc2.get_one(db, vec![]).await.unwrap();
            // println!("doc: {:#?}", doc2);

            assert_eq!(doc2.role, doc.role);

            let mut doc3 = Member::with_pk(gid, uid);
            doc3.get_one(db, vec!["role".to_string()]).await.unwrap();
            assert_eq!(doc3.role, 2i8);
            assert_eq!(doc3._fields, vec!["role"]);
        }

        // update role
        {
            let mut doc = Member::with_pk(gid, uid);
            doc.get_one(db, vec![]).await.unwrap();

            let res = doc.update_role(db, 2, doc.updated_at - 1).await;
            assert!(res.is_err());

            let res = doc.update_role(db, 3, doc.updated_at).await;
            assert!(res.is_err());
            let res = doc.update_role(db, -3, doc.updated_at).await;
            assert!(res.is_err());

            let res = doc.update_role(db, 2, doc.updated_at).await.unwrap();
            assert!(!res);

            let res = doc.update_role(db, 1, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.update_role(db, 1, doc.updated_at).await.unwrap();
            assert!(!res);
        }

        // update priority
        {
            let mut doc = Member::with_pk(gid, uid);
            doc.get_one(db, vec![]).await.unwrap();

            let res = doc.update_priority(db, -2, doc.updated_at).await;
            assert!(res.is_err());
            let res = doc.update_priority(db, 3, doc.updated_at).await;
            assert!(res.is_err());

            let res = doc.update_priority(db, 2, doc.updated_at - 1).await;
            assert!(res.is_err());

            let res = doc.update_priority(db, 2, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.update_priority(db, 1, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.update_priority(db, 1, doc.updated_at).await.unwrap();
            assert!(!res);
        }

        // delete
        {
            let mut doc = Member::with_pk(gid, uid);
            doc.get_one(db, vec![]).await.unwrap();

            let res = doc.delete(db, doc.updated_at).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 409);

            let res = doc.update_role(db, -2, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.delete(db, doc.updated_at - 1).await;
            assert!(res.is_err());
            let err: erring::HTTPError = res.unwrap_err().into();
            assert_eq!(err.code, 409);

            let res = doc.delete(db, doc.updated_at).await.unwrap();
            assert!(res);

            let res = doc.delete(db, doc.updated_at).await.unwrap();
            assert!(!res);
        }
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn list_members_works() {
        let db = get_db().await;
        let gid = xid::new();

        let mut docs: Vec<Member> = Vec::new();
        for _i in 0..10 {
            let mut doc = Member::with_pk(gid, xid::new());
            doc.save(db).await.unwrap();
            docs.push(doc)
        }
        assert_eq!(docs.len(), 10);

        let first = Member::list_members(db, gid, Vec::new(), 1, None, None)
            .await
            .unwrap();
        assert_eq!(first.len(), 1);

        let mut first = first[0].to_owned();
        assert_eq!(first.gid, docs.first().unwrap().gid);
        assert_eq!(first.uid, docs.first().unwrap().uid);

        first.update_role(db, 1, first.updated_at).await.unwrap();
        let res = Member::list_members(db, gid, vec![], 100, None, None)
            .await
            .unwrap();
        assert_eq!(res.len(), 10);

        let res = Member::list_members(db, gid, vec![], 100, None, Some(1))
            .await
            .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].uid, docs.first().unwrap().uid);

        let res = Member::list_members(db, gid, vec![], 5, None, None)
            .await
            .unwrap();
        assert_eq!(res.len(), 5);
        assert_eq!(res[4].uid, docs[4].uid);

        let res = Member::list_members(db, gid, vec![], 5, Some(docs[4].uid), None)
            .await
            .unwrap();
        assert_eq!(res.len(), 5);
        assert_eq!(res[4].uid, docs[9].uid);

        let res = Member::list_members(db, gid, vec![], 5, Some(docs[4].uid), Some(1))
            .await
            .unwrap();
        assert_eq!(res.len(), 0);
    }

    // #[tokio::test(flavor = "current_thread")]
    async fn list_groups_works() {
        let db = get_db().await;
        let uid = xid::new();

        let mut docs: Vec<Member> = Vec::new();
        for i in 0..10 {
            let mut group = Group::with_pk(xid::new());
            group.uid = xid::new();
            group.name = format!("Group {}", i);
            group.save(db).await.unwrap();

            let mut doc = Member::with_pk(group.id, uid);
            doc.save(db).await.unwrap();
            docs.push(doc)
        }

        assert_eq!(docs.len(), 10);

        let latest = Member::list_groups(db, uid, Vec::new(), 1, None, None)
            .await
            .unwrap();
        assert_eq!(latest.len(), 1);

        let latest = latest[0].to_owned();
        assert_eq!(latest.id, docs.last().unwrap().gid);

        let mut latest = docs[9].to_owned();
        latest
            .update_priority(db, 1, latest.updated_at)
            .await
            .unwrap();
        let res = Member::list_groups(db, uid, vec![], 100, None, None)
            .await
            .unwrap();
        assert_eq!(res.len(), 10);

        let res = Member::list_groups(db, uid, vec![], 100, None, Some(1))
            .await
            .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, docs.last().unwrap().gid);

        let res = Member::list_groups(db, uid, vec![], 5, None, None)
            .await
            .unwrap();
        assert_eq!(res.len(), 5);
        assert_eq!(res[4].id, docs[5].gid);

        let res = Member::list_groups(db, uid, vec![], 5, Some(docs[5].gid), None)
            .await
            .unwrap();
        assert_eq!(res.len(), 5);
        assert_eq!(res[4].id, docs[0].gid);

        let res = Member::list_groups(db, uid, vec![], 5, Some(docs[5].gid), Some(1))
            .await
            .unwrap();
        assert_eq!(res.len(), 0);
    }
}
