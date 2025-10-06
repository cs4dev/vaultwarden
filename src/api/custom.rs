use rocket::serde::json::Json;
use rocket::{http::Status, Route, request::{FromRequest, Outcome, Request}};
use serde::{Deserialize, Serialize};

use crate::{
    api::{EmptyResult, JsonResult},
    db::{models::*, DbConn},
    mail, CONFIG,
    auth::{encode_jwt, generate_invite_claims},
};

pub const FAKE_ADMIN_UUID: &str = "00000000-0000-0000-0000-000000000000";

pub struct AdminToken;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let api_key = request.headers().get_one("admin_token");
        
        match api_key {
            Some(key) if !key.is_empty() => {
                if let Some(expected_key) = CONFIG.admin_token() {
                    if key == expected_key {
                        Outcome::Success(AdminToken)
                    } else {
                        Outcome::Error((Status::Unauthorized, "Invalid admin_key"))
                    }
                } else {
                    Outcome::Error((Status::InternalServerError, "admin_key not configured"))
                }
            }
            _ => Outcome::Error((Status::Unauthorized, "Missing admin_key header"))
        }
    }
}

pub fn routes() -> Vec<Route> {
    routes![invite_user, get_user_by_id]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteData {
    email: String,
}

#[post("/invite", format = "application/json", data = "<data>")]
async fn invite_user(_auth: AdminToken, data: Json<InviteData>, mut conn: DbConn) -> JsonResult {
    let data: InviteData = data.into_inner();
    if let Some(existing_user) = User::find_by_mail(&data.email, &mut conn).await {
        return Ok(Json(existing_user.to_json(&mut conn).await))
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

    Ok(Json(user.to_json(&mut conn).await))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserResponse {
    email: Option<String>,
    url: Option<String>,
}

#[get("/user/<user_id>")]
async fn get_user_by_id(_auth: AdminToken, user_id: String, mut conn: DbConn) -> JsonResult {
    let user_uuid = UserId::from(user_id);

    match User::find_by_uuid(&user_uuid, &mut conn).await {
        Some(user) => {
            if user.akey.is_empty() {
                let claims = generate_invite_claims(
                    user.uuid.clone(),
                    user.email.clone(),
                    FAKE_ADMIN_UUID.to_string().into(),
                    FAKE_ADMIN_UUID.to_string().into(),
                    None,
                );
                let invite_token = encode_jwt(&claims);
                let mut query = url::Url::parse("https://query.builder").unwrap();
                {
                    let mut query_params = query.query_pairs_mut();
                    query_params
                        .append_pair("email", &user.email)
                        .append_pair("organizationName", &CONFIG.invitation_org_name())
                        .append_pair("organizationId", &FAKE_ADMIN_UUID.to_string())
                        .append_pair("organizationUserId", &FAKE_ADMIN_UUID.to_string())
                        .append_pair("token", &invite_token);
            
                    if CONFIG.sso_enabled() && CONFIG.sso_only() {
                        query_params.append_pair("orgUserHasExistingUser", "false");
                    } else if user.private_key.is_some() {
                        query_params.append_pair("orgUserHasExistingUser", "true");
                    }
                }
                let Some(query_string) = query.query() else {
                    err!("Failed to build invite URL query parameters")
                };
                let url = format!("{}/#/accept-organization/?{}", CONFIG.domain(), query_string);

                Ok(Json(serde_json::to_value(UserResponse {
                    email: Some(user.email),
                    url: Some(url.clone()),
                }).unwrap()))
            } else {
                Ok(Json(serde_json::to_value(UserResponse {
                    email: Some(user.email),
                    url: None,
                }).unwrap()))
            }
        }
        None => err_code!("User not found", Status::NotFound.code),
    }
}