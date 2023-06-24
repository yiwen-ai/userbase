


use axum_web::context::unix_ms;
use axum_web::erring::HTTPError;
use scylla_orm::{ColumnsMap, CqlValue, ToCqlVal};
use scylla_orm_macros::CqlOrm;

use crate::db::{
    scylladb,
    scylladb::{extract_applied, Query},
};

use super::{Group};

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

        let rows = if let Some(id) = page_token {
            if role.is_none() {
                let query = Query::new(format!(
                "SELECT {} FROM member WHERE gid=? AND uid<? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                fields.clone().join(",")))
                .with_page_size(page_size as i32);
                let params = (gid.to_cql(), id.to_cql(), page_size as i32);
                db.execute_paged(query, params, None).await?
            } else {
                let query = Query::new(format!(
                    "SELECT {} FROM member WHERE gid=? AND id<? AND role=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                    fields.clone().join(","))).with_page_size(page_size as i32);
                let params = (gid.to_cql(), id.to_cql(), role.unwrap(), page_size as i32);
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
        status: Option<i8>,
    ) -> anyhow::Result<Vec<Group>> {
        let fields = Self::select_fields(select_fields, true)?;

        let member_fields = vec![
            "gid".to_string(),
            "role".to_string(),
            "status".to_string(),
            "created_at".to_string(),
        ];
        let rows = if status.is_none() {
            let query = Query::new(format!(
                "SELECT {} FROM member WHERE uid=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                member_fields.clone().join(",")
            ))
            .with_page_size(1000i32);
            let params = (uid.to_cql(), 1000i32);
            db.execute_paged(query, params, None).await?
        } else {
            let query = Query::new(format!(
                    "SELECT {} FROM member WHERE uid=? AND status=? LIMIT ? BYPASS CACHE USING TIMEOUT 3s",
                    member_fields.clone().join(","))).with_page_size(1000i32);
            let params = (uid.to_cql(), status.unwrap(), 1000i32);
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

        members.sort_by(|a, b| a.created_at.partial_cmp(&b.created_at).unwrap());
        if let Some(gid) = page_token {
            let mut iter = members.split_inclusive(|member| member.gid == gid).skip(1);
            if let Some(rt) = iter.next() {
                if !rt.is_empty() {
                    members = rt.to_vec();
                }
            }
        }
        if members.len() > page_size as usize {
            members.truncate(page_size as usize);
        }
        let mut res: Vec<Group> = Vec::with_capacity(members.len());
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
