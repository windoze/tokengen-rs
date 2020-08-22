use std::collections::HashMap;
use std::{thread, time};

use serde::{Deserialize, Serialize};

use std::process::exit;
use crate::profile::{send_request, AADToken, is_expired};
use clipboard::{ClipboardContext, ClipboardProvider};
use webbrowser::{open_browser, Browser};
use chrono::Utc;

#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UserToken {
    error: String,
    scope: String,
    id_token: String,
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    expires_on: i64,
}

impl AADToken for UserToken {
    fn is_expired(&self) -> bool {
        is_expired(self.expires_on)
    }

    fn get_token(&self) -> String {
        // TODO: Command line option to use id_token or access_token
        // if self.access_token.is_empty() {
        //     self.id_token.clone()
        // } else {
        //     self.access_token.clone()
        // }
        self.id_token.clone()
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserProfile {
    pub name: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub authority: String,
    #[serde(default)]
    pub scope: String,
}

#[derive(Clone, Default, PartialEq, Debug, Serialize, Deserialize)]
struct DevCodeResp {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
    message: String,
}

impl UserProfile {
    pub fn get_token(&self) -> UserToken {
        // TODO: Refresh token silently

        // Refer to:
        // https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
        let url = format!("{}/{}/oauth2/v2.0/devicecode", self.authority, self.tenant);

        let mut form: HashMap<&str, &str> = HashMap::new();
        form.insert("client_id", &self.client_id);
        form.insert("scope", &self.scope);

        let resp = send_request(&url, &form, false);

        let dcresp: DevCodeResp = match resp.json() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ERROR: Failed to decode response, error is {:#?}.", e);
                exit(2);
            }
        };

        let url = format!("{}/{}/oauth2/v2.0/token", self.authority, self.tenant);

        let mut form: HashMap<&str, &str> = HashMap::new();
        form.insert("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
        form.insert("client_id", &self.client_id);
        form.insert("device_code", &dcresp.device_code);

        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents(dcresp.user_code).unwrap();
        open_browser(Browser::Default, &dcresp.verification_uri).unwrap();

        for _ in 1..=dcresp.expires_in {
            let resp = send_request(&url, &form, true);
            let mut token: UserToken = match resp.json() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: Failed to decode response, error is {:#?}.", e);
                    exit(2);
                }
            };
            if token.error.is_empty() {
                token.expires_on = Utc::now().timestamp() + token.expires_in - 5;   // Some seconds passed
                return token;
            }
            thread::sleep(time::Duration::from_secs(dcresp.interval));
        }

        eprintln!("ERROR: Failed to get code.");
        exit(2);
    }

    pub fn refresh_token(&self, token: &UserToken) -> Option<UserToken> {
        // https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#refresh-the-access-token
        let url = format!("{}/{}/oauth2/v2.0/token", self.authority, self.tenant);

        let mut form: HashMap<&str, &str> = HashMap::new();
        form.insert("client_id", &self.client_id);
        form.insert("scope", &self.scope);
        form.insert("refresh_token", &token.refresh_token);
        form.insert("grant_type", "refresh_token");

        let resp = send_request(&url, &form, false);

        let mut token: UserToken = match resp.json() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("WARNING: Failed to refresh token, error is {:#?}.", e);
                return None;
            }
        };

        token.expires_on = Utc::now().timestamp() + token.expires_in - 5;   // Some seconds passed
        Some(token)
    }

    pub fn is_valid(&self) -> bool {
        !(self.client_id.is_empty()
            || self.authority.is_empty()
            || self.tenant.is_empty()
            || self.scope.is_empty())
    }

    pub fn get_key(&self) -> String {
        format!("User:{}\t{}\t{}\t{}", self.client_id, self.tenant, self.authority, self.scope)
    }
}

