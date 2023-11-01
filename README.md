gauth
=====

[![CodeScene Code Health](https://codescene.io/projects/45882/status-badges/code-health)](https://codescene.io/projects/45882)

The library supports the following Google Auth flows:

* [OAuth2 for installed apps](https://developers.google.com/identity/protocols/oauth2#installed)
* [Service Accounts](https://developers.google.com/identity/protocols/oauth2/service-account)


```toml
[dependencies]
gauth = "0.6"
```

#### OAuth2

1. Create your application in [Google API Console](https://console.developers.google.com/apis/credentials)  
   a. `Credentials` > `Create credentials` > `OAuth client ID`  
   b. Set application type to `Other`  
   c. Enter your application name  
   d. `Download JSON` configuration of the newly created application  


**Client implementation with defaults**

```rust,no_run
use gauth::app::Auth;

#[tokio::main]
async fn access_token() {
    let auth_client = Auth::from_file(
        "my_credentials.json",
        vec!["https://www.googleapis.com/auth/drive"],
    )
    .unwrap();

    let token = auth_client.access_token().await.unwrap();
    println!("access token: {}", token);
}
```

**Custom app name and handler**: access token will be stored in `$HOME/.{app_name}/access_token.json`

To assign a custom directory as access token caching, set env var value: `GAUTH_TOKEN_DIR`

```rust,no_run
use gauth::app::Auth;

#[tokio::main]
async fn access_token() {
    let auth_handler = |consent_uri: String| -> Result<String, Box<dyn std::error::Error>> {
        // business logic
        Ok("auth_code".to_owned())
    };

    let mut auth_client = Auth::from_file(
        "my_credentials.json",
        vec!["https://www.googleapis.com/auth/drive"],
    )
    .unwrap();

    let auth_client = auth_client.app_name("new_name").handler(auth_handler);
    let token = auth_client.access_token().await.unwrap();
    println!("access token: {}", token);
}
```

#### Service Account

Follow instructions for [creating a service account](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount). After a service account key has been created,
it can be used to obtain an access token.

```rust,no_run
use gauth::serv_account::ServiceAccount;

#[tokio::main]
async fn access_token() {
    let scopes = vec!["https://www.googleapis.com/auth/drive"];
    let key_path = "test_fixtures/service-account-key.json";

    let mut service_account = ServiceAccount::from_file(key_path, scopes);
    let access_token = service_account.access_token().await.unwrap();

    println!("access token {}:", access_token);
}
```

## License

License under either or:

* [MIT](LICENSE-MIT)
* [Apache License, Version 2.0](LICENSE-APACHE)
