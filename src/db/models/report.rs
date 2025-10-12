use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;

use super::{OrganizationId, UserId};
use crate::{
    api::EmptyResult,
    db::DbConn,
    error::MapResult,
    util::get_uuid,
};
use macros::UuidFromParam;

db_object! {
    #[derive(Identifiable, Queryable, Insertable, AsChangeset, Selectable)]
    #[diesel(table_name = reports)]
    #[diesel(treat_none_as_null = true)]
    #[diesel(primary_key(uuid))]
    pub struct Report {
        pub uuid: ReportId,
        pub user_uuid: Option<UserId>,
        pub org_uuid: Option<OrganizationId>,
        pub exposed_count: i32,
        pub created_at: NaiveDateTime,
        pub last_updated_at: NaiveDateTime,
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    UuidFromParam,
)]
#[deref(forward)]
#[from(forward)]
pub struct ReportId(String);

impl Report {
    pub fn new_personal(user_uuid: UserId, exposed_count: i32) -> Self {
        let now = Utc::now().naive_utc();
        
        Self {
            uuid: ReportId::from(get_uuid()),
            user_uuid: Some(user_uuid),
            org_uuid: None,
            exposed_count,
            created_at: now,
            last_updated_at: now,
        }
    }
    
    pub fn new_org(org_uuid: OrganizationId, exposed_count: i32) -> Self {
        let now = Utc::now().naive_utc();
        
        Self {
            uuid: ReportId::from(get_uuid()),
            user_uuid: None,
            org_uuid: Some(org_uuid),
            exposed_count,
            created_at: now,
            last_updated_at: now,
        }
    }
    
    pub async fn find_by_user_personal(user_uuid: &UserId, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            reports::table
                .filter(reports::user_uuid.eq(user_uuid))
                .filter(reports::org_uuid.is_null())
                .first::<ReportDb>(conn)
                .ok()
                .from_db()
        }}
    }
    
    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &mut DbConn) -> Option<Self> {
        db_run! { conn: {
            reports::table
                .filter(reports::user_uuid.is_null())
                .filter(reports::org_uuid.eq(org_uuid))
                .first::<ReportDb>(conn)
                .ok()
                .from_db()
        }}
    }
    
    pub fn update_exposed_count(&mut self, new_count: i32) {
        self.exposed_count = if new_count < 0 { 0 } else { new_count };
        self.last_updated_at = Utc::now().naive_utc();
    }
    
    pub async fn save(&mut self, conn: &mut DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                let value = ReportDb::to_db(self);
                diesel::insert_into(reports::table)
                    .values(&value)
                    .on_conflict(reports::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving report")
            }
            postgresql {
                let value = ReportDb::to_db(self);
                diesel::insert_into(reports::table)
                    .values(&value)
                    .on_conflict(reports::uuid)
                    .do_update()
                    .set(&value)
                    .execute(conn)
                    .map_res("Error saving report")
            }
        }
    }
}

