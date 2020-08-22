use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::process::exit;

use chrono::{DateTime, NaiveDateTime, Utc};
use dirs::cache_dir;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};

pub use app_profile::AppProfile;
pub use user_profile::UserProfile;

use crate::profile::app_profile::AppToken;
use crate::profile::user_profile::UserToken;

mod user_profile;
mod app_profile;

fn send_request(url: &str, form: &HashMap<&str, &str>, ignore_error: bool) -> Response {
    let resp = match Client::builder().build().unwrap().post(url).form(form).send() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: Request failed, error is {:#?}", e);
            exit(1);
        }
    };
    if !ignore_error && !resp.status().is_success() {
        eprintln!("ERROR: Request failed, status is {}", resp.status());
        exit(i32::from(resp.status().as_u16()))
    }

    resp
}

fn is_expired(expires_on: i64) -> bool {
    let exp = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(expires_on, 0), Utc);
    let duration = exp.signed_duration_since(Utc::now());
    duration.num_minutes() < 1
}

pub trait AADToken {
    fn is_expired(&self) -> bool;
    fn get_token_string(&self, token_type: TokenType) -> String;
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Token {
    App(AppToken),
    User(UserToken),
}

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum TokenType {
    Access,
    Id,
    AccessOrId,
    IdOrAccess,
}

impl Default for Token {
    fn default() -> Self {
        Token::App(AppToken::default())
    }
}

impl AADToken for Token {
    fn is_expired(&self) -> bool {
        match self {
            Token::User(t) => t.is_expired(),
            Token::App(t) => t.is_expired()
        }
    }

    fn get_token_string(&self, token_type: TokenType) -> String {
        match self {
            Token::User(t) => t.get_token_string(token_type),
            Token::App(t) => t.get_token_string(token_type)
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(tag = "Type")]
pub enum Profile {
    App(AppProfile),
    User(UserProfile),
}

impl Profile {
    fn load_cache() -> HashMap<String, Token> {
        let mut cache_dir = cache_dir().unwrap();
        cache_dir.push("tokengen");
        match create_dir_all(cache_dir.as_path()) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("WARNING: Unable to create cache directory '{}', error is {:#?}.", cache_dir.to_string_lossy(), e);
                return HashMap::new();
            }
        }

        let mut cache_filename = cache_dir.clone();
        cache_filename.push("cache.json");
        let cache_file = match File::open(cache_filename.as_path()) {
            Ok(f) => f,
            Err(_) => {
                return HashMap::new();
            }
        };

        match serde_json::from_reader(cache_file) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("WARNING: Unable to load cache file at '{}', error is {:#?}.", cache_filename.to_string_lossy(), e);
                HashMap::new()
            }
        }
    }

    fn save_cache(cache: HashMap<String, Token>) {
        let mut cache_dir = cache_dir().unwrap();
        cache_dir.push("tokengen");
        match create_dir_all(cache_dir.as_path()) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("WARNING: Unable to create cache directory '{}', error is {:#?}.", cache_dir.to_string_lossy(), e);
                return;
            }
        }

        let mut cache_filename = cache_dir.clone();
        cache_filename.push("cache.json");
        let cache_file = match File::create(cache_filename.as_path()) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("WARNING: Unable to create cache file at '{}', error is {:#?}.", cache_filename.to_string_lossy(), e);
                return;
            }
        };

        let output: HashMap<String, Token> = cache.into_iter().filter(|(_, v)|
            !v.is_expired()
        ).collect();

        match serde_json::to_writer(cache_file, &output) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("WARNING: Unable to save cache to '{}', error is {:#?}.", cache_filename.to_string_lossy(), e);
            }
        };
    }

    fn get_key(&self) -> String {
        match self {
            Profile::App(p) => p.get_key(),
            Profile::User(p) => p.get_key()
        }
    }

    pub fn get_name(&self) -> &str {
        match self {
            Profile::App(p) => &p.name,
            Profile::User(p) => &p.name
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            Profile::App(p) => p.is_valid(),
            Profile::User(p) => p.is_valid()
        }
    }

    pub fn refresh_token(&self, token: &Token) -> Option<Token> {
        match self {
            Profile::App(_) => None,
            Profile::User(p) => match token {
                Token::User(t) => p.refresh_token(t).map(|t| Token::User(t)),
                Token::App(_) => None
            }
        }
    }

    pub fn get_token(&self) -> Token {
        let mut cache = Profile::load_cache();

        match cache.get(&self.get_key()) {
            Some(t) => {
                if t.is_expired() {
                    // Try to refresh this token
                    match self.refresh_token(t) {
                        Some(t) => {
                            // Refreshed, save and return
                            cache.insert(self.get_key(), t.clone());
                            Profile::save_cache(cache);
                            return t.clone();
                        }
                        // Failed to refresh
                        None => ()
                    }
                } else {
                    // Not expired
                    return t.clone();
                }
            }
            // Not found in cache
            None => ()
        }

        let token = match self {
            Profile::App(p) => Token::App(p.get_token()),
            Profile::User(p) => Token::User(p.get_token())
        };

        // Save and return
        cache.insert(self.get_key(), token.clone());
        Profile::save_cache(cache);
        token
    }

    // Override this profile
    pub fn with_overrides(
        &self,
        client_id: &str,
        secret: &str,
        tenant: &str,
        authority: &str,
        resource: &str,
        scope: &str,
    ) -> Profile {
        match self {
            Profile::App(p) => {
                Profile::App(AppProfile {
                    name: p.name.to_owned(),
                    client_id: if client_id.is_empty() { p.client_id.to_owned() } else { client_id.to_owned() },
                    secret: if secret.is_empty() { p.secret.to_owned() } else { secret.to_owned() },
                    tenant: if tenant.is_empty() { p.tenant.to_owned() } else { tenant.to_owned() },
                    authority: if authority.is_empty() { p.authority.to_owned() } else { authority.to_owned() },
                    resource: if resource.is_empty() { p.resource.to_owned() } else { resource.to_owned() },
                })
            }
            Profile::User(p) => {
                Profile::User(UserProfile {
                    name: p.name.to_owned(),
                    client_id: if client_id.is_empty() { p.client_id.to_owned() } else { client_id.to_owned() },
                    tenant: if tenant.is_empty() { p.tenant.to_owned() } else { tenant.to_owned() },
                    authority: if authority.is_empty() { p.authority.to_owned() } else { authority.to_owned() },
                    scope: if scope.is_empty() { p.scope.to_owned() } else { scope.to_owned() },
                })
            }
        }
    }

    // Fill missing fields with defaults
    pub fn with_defaults(
        &self,
        client_id: &str,
        secret: &str,
        tenant: &str,
        authority: &str,
        scope: &str,
    ) -> Profile {
        match self {
            Profile::App(p) => {
                Profile::App(AppProfile {
                    name: p.name.to_owned(),
                    client_id: if p.client_id.is_empty() { client_id.to_owned() } else { p.client_id.to_owned() },
                    secret: if p.secret.is_empty() { secret.to_owned() } else { p.secret.to_owned() },
                    tenant: if p.tenant.is_empty() { tenant.to_owned() } else { p.tenant.to_owned() },
                    authority: if p.authority.is_empty() { authority.to_owned() } else { p.authority.to_owned() },
                    resource: p.resource.to_owned(),
                })
            }
            Profile::User(p) => {
                Profile::User(UserProfile {
                    name: p.name.to_owned(),
                    client_id: if p.client_id.is_empty() { client_id.to_owned() } else { p.client_id.to_owned() },
                    tenant: if p.tenant.is_empty() { tenant.to_owned() } else { p.tenant.to_owned() },
                    authority: if p.authority.is_empty() { authority.to_owned() } else { p.authority.to_owned() },
                    scope: if p.scope.is_empty() { scope.to_owned() } else { p.scope.to_owned() },
                })
            }
        }
    }


    pub fn create(
        profile_type: &str,
        client_id: &str,
        secret: &str,
        tenant: &str,
        authority: &str,
        resource: &str,
        scope: &str,
    ) -> Profile {
        match profile_type {
            "App" => {
                Profile::App(AppProfile {
                    name: String::from(""),
                    client_id: client_id.to_string(),
                    secret: secret.to_string(),
                    tenant: tenant.to_string(),
                    authority: authority.to_string(),
                    resource: resource.to_string(),
                })
            }
            "User" => {
                Profile::User(UserProfile {
                    name: String::from(""),
                    client_id: client_id.to_string(),
                    tenant: tenant.to_string(),
                    authority: authority.to_string(),
                    scope: scope.to_string(),
                })
            }
            _ => {
                eprintln!("ERROR: Unknown profile type '{}'.", profile_type);
                exit(3)
            }
        }
    }
}
