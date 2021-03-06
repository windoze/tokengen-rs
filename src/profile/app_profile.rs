use std::collections::HashMap;
use std::process::exit;

use serde::{Deserialize, Serialize};

use crate::profile::{AADToken, is_expired, send_request, TokenType};

#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppToken {
    id_token: String,
    access_token: String,
    expires_on: String,
}

impl AADToken for AppToken {
    fn is_expired(&self) -> bool {
        match self.expires_on.parse() {
            Ok(v) => is_expired(v),
            Err(_) => {
                eprintln!("WARNING: Invalid token expiration value.");
                return true;
            }
        }
    }

    fn get_token_string(&self, token_type: TokenType) -> String {
        match token_type {
            TokenType::Access => &self.access_token,
            TokenType::Id => &self.id_token,
            TokenType::AccessOrId => (if self.access_token.is_empty() { &self.id_token } else { &self.access_token }),
            TokenType::IdOrAccess => (if self.id_token.is_empty() { &self.access_token } else { &self.id_token }),
        }.clone()
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AppProfile {
    pub name: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub authority: String,
    pub resource: String,
}

impl AppProfile {
    pub fn get_token(&self) -> AppToken {
        // Refer to:
        // https://docs.microsoft.com/en-us/azure/active-directory/azuread-dev/v1-oauth2-client-creds-grant-flow
        let url = format!("{}/{}/oauth2/token", self.authority, self.tenant);

        let mut form = HashMap::new();
        form.insert("grant_type", "client_credentials");
        form.insert("client_id", &self.client_id);
        form.insert("client_secret", &self.secret);
        form.insert("resource", &self.resource);

        let resp = send_request(&url, &form, false);

        resp.json().map_err(|e| {
            eprintln!("ERROR: Failed to decode response, error is {:#?}.", e);
            exit(2);
        }).unwrap()
    }

    pub fn is_valid(&self) -> bool {
        !(self.client_id.is_empty()
            || self.secret.is_empty()
            || self.tenant.is_empty()
            || self.authority.is_empty())
    }

    pub fn get_key(&self) -> String {
        format!("App:{}\t{}\t{}\t{}", self.client_id, self.tenant, self.authority, self.resource)
    }
}

