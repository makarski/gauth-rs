rust_google_oauth2
================

The library supports the following flows:

* [OAuth2 for installed apps](https://developers.google.com/identity/protocols/oauth2#installed)
* [Service Accounts](https://developers.google.com/identity/protocols/oauth2/service-account)


```toml
[dependencies]
gauth = "0.4.0"
```

#### OAuth2

1. Create your application in [Google API Console](https://console.developers.google.com/apis/credentials)  
   a. `Credentials` > `Create credentials` > `OAuth client ID`  
   b. Set application type to `Other`  
   c. Enter your application name  
   d. `Download JSON` configuration of newly created application  


Sample client implementation

```rust,no_run
fn main() {
    // define consent URL handler
    // returns an auth. code which is then exchanged against access token
    let handle_auth = |consent_url: String| -> Result<String, <Box std:error:Error>> {
        println!("> open the link in browser\n\n{}\n", consent_url);
        println!("> enter the auth. code\n");

        let mut auth_code = String::new();
        io::stdin().read_line(&mut auth_code)?;

        Ok(auth_code)
    }

    let auth_client = gauth::Auth::new(
        "my-new-application",
        &[
            "https://www.googleapis.com/auth/drive.readonly",
        ],
        PathBuf::from("/my-google-credentials/oauth-credentials.json"),
    );

    let token = auth_client
        .access_token(handle_auth)
        .expect("failed to retrieve access token");

    println!("obtained token: {:?}", token);
}
```

#### Service Account

Follow instructions for [creating a service account](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount). After a service account key has been created,
it can be used to obtain an access token.

```rust,no_run
use gauth::serv_account::ServiceAccount;

fn access_token() {
    let scopes = vec!["https://www.googleapis.com/auth/drive"];
    let key_path = "test_fixtures/service-account-key.json";

    let mut service_account = ServiceAccount::from_file(key_path, scopes);
    let access_token = service_account.access_token().unwrap();

    println!("access token {}:", access_token);
}
```

## License

License under either or:

* [MIT](LICENSE-MIT)
* [Apache License, Version 2.0](LICENSE-APACHE)
