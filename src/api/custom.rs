use rocket::serde::json::Json;
use rocket::{http::Status, Route, request::{FromRequest, Outcome, Request}};
use serde::{Deserialize, Serialize};

use crate::{
    api::{EmptyResult, JsonResult},
    db::{models::*, DbConn},
    mail, CONFIG,
};

pub const FAKE_ADMIN_UUID: &str = "00000000-0000-0000-0000-000000000000";

pub struct VWApi;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for VWApi {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let api_key = request.headers().get_one("x-vaultwarden-api");
        
        match api_key {
            Some(key) if !key.is_empty() => {
                if let Some(expected_key) = CONFIG.x_vaultwarden_api() {
                    if key == expected_key {
                        Outcome::Success(VWApi)
                    } else {
                        Outcome::Error((Status::Unauthorized, "Invalid x-vaultwarden-api"))
                    }
                } else {
                    Outcome::Error((Status::InternalServerError, "x-vaultwarden-api not configured"))
                }
            }
            _ => Outcome::Error((Status::Unauthorized, "Missing x-vaultwarden-api header"))
        }
    }
}

pub fn routes() -> Vec<Route> {
    routes![invite_user, get_user_details, exposed]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteData {
    email: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InviteResponse {
    user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExposedData {
    user_id: String,
    org: std::collections::HashMap<String, i32>,
    me: i32,
}

#[post("/invite", format = "application/json", data = "<data>")]
async fn invite_user(_auth: VWApi, data: Json<InviteData>, mut conn: DbConn) -> JsonResult {
    let data: InviteData = data.into_inner();
    if let Some(existing_user) = User::find_by_mail(&data.email, &mut conn).await {
        return Ok(Json(serde_json::to_value(InviteResponse {
            user_id: existing_user.uuid.to_string(),
        }).unwrap()))
    }

    let mut user = User::new(data.email, None);

    async fn _generate_invite(user: &User, conn: &mut DbConn) -> EmptyResult {
        if CONFIG.mail_enabled() {
            let org_id: OrganizationId = FAKE_ADMIN_UUID.to_string().into();
            let member_id: MembershipId = FAKE_ADMIN_UUID.to_string().into();
            mail::send_admin_invite(user, org_id, member_id, &CONFIG.invitation_org_name(), None).await
        } else {
            let invitation = Invitation::new(&user.email);
            invitation.save(conn).await
        }
    }

    _generate_invite(&user, &mut conn).await.map_err(|e| e.with_code(Status::InternalServerError.code))?;
    user.save(&mut conn).await.map_err(|e| e.with_code(Status::InternalServerError.code))?;

    Ok(Json(serde_json::to_value(InviteResponse {
        user_id: user.uuid.to_string(),
    }).unwrap()))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserDetailsResponse {
    status: String,
    org_id: Option<String>,
    members_count: i64,
    exposed_count: i64,
    last_updated_at: Option<String>,
}

#[get("/user/<user_id>/details")]
async fn get_user_details(_auth: VWApi, user_id: String, mut conn: DbConn) -> JsonResult {
    let user_uuid = UserId::from(user_id);

    match User::find_by_uuid(&user_uuid, &mut conn).await {
        Some(_user) => {
            // Get user memberships to determine status
            let memberships = Membership::find_by_user(&user_uuid, &mut conn).await;
            
            // Status: Active if has membership, else Pending
            let status = if memberships.is_empty() {
                "Pending".to_string()
            } else {
                "Active".to_string()
            };
            
            // Members count: number of members in the user's organization (0 if no organization)
            let members_count = if let Some(membership) = memberships.first() {
                let org_memberships = Membership::find_by_org(&membership.org_uuid, &mut conn).await;
                org_memberships.len() as i64
            } else {
                0
            };
            
            // Exposed count and last_updated_at: search reports by org_uuid (0 if no organization)
            let (exposed_count, last_updated_at) = if let Some(membership) = memberships.first() {
                match Report::find_by_org(&membership.org_uuid, &mut conn).await {
                    Some(report) => (report.exposed_count, Some(report.last_updated_at.and_utc().to_rfc3339())),
                    None => (0, None),
                }
            } else {
                (0, None)
            };

            let org_id = memberships.first().map(|m| m.org_uuid.to_string());

            Ok(Json(serde_json::to_value(UserDetailsResponse {
                status,
                org_id,
                members_count,
                exposed_count: exposed_count.into(),
                last_updated_at,
            }).unwrap()))
        }
        None => err_code!("User not found", Status::NotFound.code),
    }
}

#[post("/exposed", format = "application/json", data = "<data>")]
async fn exposed(data: Json<ExposedData>, mut conn: DbConn) -> EmptyResult {
    let data: ExposedData = data.into_inner();
    let user_uuid = UserId::from(data.user_id);
    
    match User::find_by_uuid(&user_uuid, &mut conn).await {
        Some(_) => {
            // Get user's memberships once for efficiency
            let user_memberships = Membership::find_by_user(&user_uuid, &mut conn).await;
            
            // 1. Store personal exposed passwords (me field) - with userId, no org
            match Report::find_by_user_personal(&user_uuid, &mut conn).await {
                Some(mut existing_report) => {
                    existing_report.update_exposed_count(data.me);
                    existing_report.save(&mut conn).await?;
                }
                None => {
                    let mut report = Report::new_personal(user_uuid.clone(), data.me);
                    report.save(&mut conn).await?;
                }
            }
            
            // 2. Store organization-specific exposed passwords (no userId, only orgId)
            for (org_id_str, exposed_count) in data.org {
                let org_uuid = OrganizationId::from(org_id_str);
                
                // Verify user is member of this organization
                let is_member = user_memberships
                    .iter()
                    .any(|membership| membership.org_uuid == org_uuid);
                
                if !is_member {
                    continue; // Skip if user is not a member of this org
                }
                
                // Find and update or create new report for this specific org (no userId stored)
                match Report::find_by_org(&org_uuid, &mut conn).await {
                    Some(mut existing_report) => {
                        existing_report.update_exposed_count(exposed_count);
                        existing_report.save(&mut conn).await?;
                    }
                    None => {
                        let mut report = Report::new_org(org_uuid, exposed_count);
                        report.save(&mut conn).await?;
                    }
                }
            }
        }
        None => (),
    }

    Ok(())
}