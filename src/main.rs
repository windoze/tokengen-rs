#[macro_use]
extern crate clap;

use std::fs::{create_dir_all, File};
use std::process::exit;

use dirs::config_dir;
use serde::{Deserialize, Serialize};

use crate::profile::{Profile, AADToken, TokenType};
use edit::edit_file;

mod profile;

#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Configuration {
    #[serde(default)]
    default_profile: String,
    #[serde(default)]
    default_client_id: String,
    #[serde(default)]
    default_secret: String,
    #[serde(default)]
    default_tenant: String,
    #[serde(default)]
    default_authority: String,
    #[serde(default)]
    default_scope: String,
    profiles: Vec<Profile>,
}

impl Configuration {
    fn new() -> Self {
        Self::default()
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

        let mut ret = match serde_json::from_reader(config_file) {
            Ok(v) => {
                v
            }
            Err(e) => {
                eprintln!("WARNING: Unable to load configuration file at '{}', error is {:#?}.", config_filename.to_string_lossy(), e);
                Self::new()
            }
        };
        if ret.default_profile.is_empty() {
            ret.default_profile = String::from("DEFAULT")
        }
        if ret.default_authority.is_empty() {
            ret.default_authority = String::from("https://login.microsoftonline.com")
        }

        ret
    }

    fn get_profile(&self,
                   name: &str,
                   profile_type: &str,
                   client_id: &str,
                   secret: &str,
                   tenant: &str,
                   authority: &str,
                   resource: &str,
                   scope: &str,
    ) -> Profile {
        let name = if name.is_empty() { &self.default_profile } else { name };
        let p = self.profiles.iter()
            .find(|&p| p.get_name() == name)
            .map(|p| p.with_overrides(client_id, secret, tenant, authority, resource, scope))
            .map(|p| p.with_defaults(
                &self.default_client_id,
                &self.default_secret,
                &self.default_tenant,
                &self.default_authority,
                &self.default_scope,
            ));
        match p {
            None => {
                Profile::create(
                    profile_type,
                    client_id,
                    secret,
                    tenant,
                    authority,
                    resource,
                    scope,
                ).with_defaults(
                    &self.default_client_id,
                    &self.default_secret,
                    &self.default_tenant,
                    &self.default_authority,
                    &self.default_scope,
                )
            }
            Some(p) => p
        }
    }

    fn open_editor() {
        let mut config_dir = config_dir().unwrap();
        config_dir.push("tokengen");
        match create_dir_all(config_dir.as_path()) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("WARNING: Unable to create config directory '{}', error is {:#?}.", config_dir.to_string_lossy(), e);
                exit(1);
            }
        }
        let mut config_filename = config_dir.clone();
        config_filename.push("config.json");
        eprintln!("Opening editor to edit config file at '{}'...", config_filename.to_string_lossy());
        edit_file(config_filename).unwrap_or_default();
    }
}

fn main() {
    let mut app = clap_app!(tokengen =>
        (version: "0.1")
        (author: "Chen Xu <windoze@0d0a.com>")
        (about: "Generate AzureAD token.")
        (@arg PROFILE: -p --profile +takes_value "Profile Name")
        (@arg TYPE: -y --type +takes_value "Profile type, can be 'App' or 'User'.")
        (@arg CLIENT_ID: -c --client_id +takes_value "[All] AAD Client Id")
        (@arg SECRET: -s --secret +takes_value "[App] Client Secret")
        (@arg TENANT: -t --tenant +takes_value "[All] AAD Tenant")
        (@arg AUTHORITY: -a --authority +takes_value "[All] Authority")
        (@arg RESOURCE: -r --resource +takes_value "[App] Resource")
        (@arg SCOPE: -o --scope +takes_value "[User] Scope")
        (@arg TOKEN_TYPE: -k --token_type +takes_value "Token Type, can be 'a', 'i', 'ai', or 'ia', default value is 'ia'.")
        (@arg FORMAT: -f --format +takes_value "Format, can be 'header' or 'raw', default value is 'header'.")
        (@arg EDIT: -e --edit "Open config file in the default editor.")
    );
    let matches = app.clone().get_matches();

    let profile = matches.value_of("PROFILE").unwrap_or_default();
    let profile_type = matches.value_of("TYPE").unwrap_or_default();
    let client_id = matches.value_of("CLIENT_ID").unwrap_or_default();
    let secret = matches.value_of("SECRET").unwrap_or_default();
    let tenant = matches.value_of("TENANT").unwrap_or_default();
    let authority = matches.value_of("AUTHORITY").unwrap_or_default();
    let resource = matches.value_of("RESOURCE").unwrap_or_default();
    let scope = matches.value_of("SCOPE").unwrap_or_default();
    let format = matches.value_of("FORMAT").unwrap_or("header");
    let token_type_str = matches.value_of("TOKEN_TYPE").unwrap_or("ia");
    let token_type = match token_type_str {
        "a" => TokenType::Access,
        "i" => TokenType::Id,
        "ai" => TokenType::AccessOrId,
        "ia" => TokenType::IdOrAccess,
        _ => {
            eprintln!("ERROR: Invalid token type {}.\n", token_type_str);
            exit(1);
        }
    };

    if matches.is_present("EDIT") {
        Configuration::open_editor();
        exit(0);
    }

    let cfg = Configuration::load();
    let profile = cfg.get_profile(
        profile,
        profile_type,
        client_id,
        secret,
        tenant,
        authority,
        resource,
        scope,
    );
    if !profile.is_valid() {
        eprintln!("ERROR: Missing command line arguments.\n");
        app.print_help().unwrap();
        println!();
        exit(1)
    }
    let token = profile.get_token();
    if format.starts_with("h") {
        print!("Authorization: Bearer {}", token.get_token_string(token_type));
    } else if format.starts_with("r") {
        print!("{}", token.get_token_string(token_type));
    }
}
