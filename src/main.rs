#[macro_use]
extern crate clap;

use std::collections::HashMap;
use std::fs::{create_dir_all, File};

use chrono::{DateTime, NaiveDateTime, Utc};
use dirs::{cache_dir, config_dir};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::process::exit;

#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Token {
    id_token: String,
    access_token: String,
    expires_on: String,
}

impl Token {
    fn is_expired(&self) -> bool {
        let sec = match self.expires_on.parse() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("WARNING: Invalid token expiration value.");
                return true;
            }
        };
        let exp = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(sec, 0), Utc);
        let duration = exp.signed_duration_since(Utc::now());
        duration.num_minutes() < 5
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Profile {
    name: String,
    client_id: String,
    secret: String,
    tenant: String,
    authority: String,
    resource: String,
}

impl Profile {
    fn new(client_id: &str,
           secret: &str,
           tenant: &str,
           authority: &str,
           resource: &str) -> Self {
        Self {
            name: String::new(),
            client_id: client_id.to_string(),
            secret: secret.to_string(),
            tenant: tenant.to_string(),
            authority: authority.to_string(),
            resource: resource.to_string(),
        }
    }

    fn get_key(&self) -> String {
        format!("{}\t{}\t{}\t{}", self.client_id, self.tenant, self.authority, self.resource)
    }

    fn load_cache(&self) -> HashMap<String, Token> {
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

    fn save_cache(&self, cache: HashMap<String, Token>) {
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

    fn get_token(&self) -> Token {
        let mut cache = self.load_cache();

        match cache.get(&self.get_key()).filter(|t| !t.is_expired()) {
            Some(t) => return t.clone(),
            None => ()
        }

        // Refer to:
        // https://docs.microsoft.com/en-us/azure/active-directory/azuread-dev/v1-oauth2-client-creds-grant-flow
        let url = format!("{}/{}/oauth2/token", self.authority, self.tenant);

        let mut form = HashMap::new();
        form.insert("grant_type", "client_credentials");
        form.insert("client_id", &self.client_id);
        form.insert("client_secret", &self.secret);
        form.insert("resource", &self.resource);

        let resp = match Client::builder().build().unwrap().post(&url).form(&form).send() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("ERROR: Request failed, error is {:#?}", e);
                exit(1);
            }
        };
        if !resp.status().is_success() {
            eprintln!("ERROR: Request failed, status is {}", resp.status());
            exit(i32::from(resp.status().as_u16()))
        }

        let token: Token = match resp.json() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ERROR: Failed to decode response, error is {:#?}.", e);
                exit(2);
            }
        };

        cache.insert(self.get_key(), token.clone());

        self.save_cache(cache);

        token
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Configuration {
    default_profile: String,
    profiles: Vec<Profile>,
}

impl Configuration {
    fn new() -> Self {
        Configuration {
            default_profile: "".to_string(),
            profiles: vec![],
        }
    }

    fn load() -> Self {
        let mut config_dir = config_dir().unwrap();
        config_dir.push("tokengen");
        match create_dir_all(config_dir.as_path()) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("WARNING: Unable to create config directory '{}', error is {:#?}.", config_dir.to_string_lossy(), e);
                return Self::new();
            }
        }

        let mut config_filename = config_dir.clone();
        config_filename.push("config.json");
        let config_file = match File::open(config_filename.as_path()) {
            Ok(f) => f,
            Err(_) => {
                return Self::new();
            }
        };

        match serde_json::from_reader(config_file) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("WARNING: Unable to load configuration file at '{}', error is {:#?}.", config_filename.to_string_lossy(), e);
                Self::new()
            }
        }
    }

    fn get_profile(&self,
                   name: &str,
                   client_id: &str,
                   secret: &str,
                   tenant: &str,
                   authority: &str,
                   resource: &str) -> Profile {
        let name = if name.is_empty() { &self.default_profile } else { name };
        for p in &self.profiles {
            if p.name == name {
                let mut ret = p.clone();
                if !client_id.is_empty() { ret.client_id = client_id.to_string(); }
                if !secret.is_empty() { ret.secret = secret.to_string(); }
                if !tenant.is_empty() { ret.tenant = tenant.to_string(); }
                if !authority.is_empty() { ret.authority = authority.to_string(); }
                if !resource.is_empty() { ret.resource = resource.to_string(); }
                return ret;
            }
        }
        Profile::new(client_id, secret, tenant, authority, resource)
    }
}

fn main() {
    let matches = clap_app!(tokengen =>
        (version: "0.1")
        (author: "Chen Xu <windoze@0d0a.com>")
        (about: "Generate AzureAD token.")
        (@arg PROFILE: -p --profile +takes_value "Profile Name")
        (@arg CLIENT_ID: -c --client_id +takes_value "AAD Client Id")
        (@arg SECRET: -s --secret +takes_value "Client Secret")
        (@arg TENANT: -t --tenant +takes_value "AAD Tenant")
        (@arg AUTHORITY: -a --authority +takes_value "Authority")
        (@arg RESOURCE: -r --resource +takes_value "Resource")
        (@arg FORMAT: -f --format +takes_value "Format, can be 'header' or 'raw'")
    ).get_matches();

    let profile = matches.value_of("PROFILE").unwrap_or_default();
    let client_id = matches.value_of("CLIENT_ID").unwrap_or_default();
    let secret = matches.value_of("SECRET").unwrap_or_default();
    let tenant = matches.value_of("TENANT").unwrap_or_default();
    let authority = matches.value_of("AUTHORITY").unwrap_or_default();
    let resource = matches.value_of("RESOURCE").unwrap_or_default();
    let format = matches.value_of("FORMAT").unwrap_or("header");

    let cfg = Configuration::load();
    let profile = cfg.get_profile(profile,
                                  client_id,
                                  secret,
                                  tenant,
                                  authority,
                                  resource,
    );
    let token = profile.get_token();
    if format.starts_with("h") {
        print!("Authorization: Bearer {}", token.access_token);
    } else if format.starts_with("r") {
        print!("{}", token.access_token);
    }
}
