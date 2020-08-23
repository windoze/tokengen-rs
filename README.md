tokengen
========

AzureAD Token Generator

Tool to generate AzureAD authentication tokens.

With everything configured, it can be used like:
```
curl -H "$(tokengen -p SomeProfile)" https://contoso.com/some_resource_requires_a_token
```

Command Line Options:
---------------------

* `-p`, `--profile`
    Select the profile to be used, see Configuration File
* `-f`, `--format`
    Output format, can be:
    + `h` CURL header format, i.e. "Authorization: Bearer XXXXX>"
    + `r` Raw format, just token string
* `-y`, `--type`
    Profile type, could be `App` or `User`
* `-k`, `--token_type`
    Token type, can be:
    + `i` id_token
    + `a` access_token
    + `ia` id_token, if it doesn't exist then access_token, this is the default value.
    + `ai` access_token, if it doesn't exist then id_token    
* `-a`, `--authority`
    [Common] Login authority URL, could be different for different Azure Cloud environments.
* `-t`, `--tenant`
    [Common] The tenant name or id.
* `-c`, `--client_id`
    [Common] For `App` type, it is the AAD App ID we used to acquire the token; for `User` type, it's the target AAD App we want to get permission.
* `-s`, `--secret`
    [App] The secret for the AAD App, can be created on the Azure Portal.
* `-r`, `--resource`
    [App] The resource you want to get access.
* `-o`, `--scope`
    [User] The scope (permission) you need.

Configuration File:
------------------
Configuration file is in JSON format:
```json
{
    "DefaultProfile": "SomeProfile",  // Default profile name
    "DefaultClientId": "XXX",         // Default Client ID(AppID) if it's missing in the profile
    "DefaultSecret": "Passw0rdxyz",   // Default secret for the Client ID
    "DefaultTenant": "contoso.com",   // Default tenant, can be name or GUID
    "DefaultScope": "openid profile user.read offline_access",  // Default scope for "User" type profile
    "Profiles": [
        {
            "Name": "SomeProfile",
            "Type": "App",
            "Resource": "http://contoso.com/someresource"
        }
        // ...
    ]
}
```
The configuration file is located under:
* Windows: `%APPDATA%\tokengen\config.json`
* MacOS: `$HOME/Library/Application Support/tokengen/config.json`
* Linux: `$HOME/.config/tokengen/config.json`

NOTE:
-----
* Make sure the "Public Client" is enabled for the AAD App, you can turn it on from the Azure portal, otherwise this tool won't work for `User` profiles.
* Add `offline_access` into the scope to enable silent refresh flow for `User` profile, otherwise you may need to login every hour.
* Different sovereign clouds have different Authority URLs, i.e.
    + Azure.com: https://login.microsoftonline.com (This is the default value.)
    + Azure.cn: https://login.chinacloudapi.cn
    
    Refer to https://docs.microsoft.com/en-us/azure/active-directory/develop/authentication-national-cloud#azure-ad-authentication-endpoints for more details. 
