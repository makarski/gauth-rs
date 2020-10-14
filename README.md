rust_google_oauth2
================

The library currently supports **Google OAuth2** flow for [installed](https://developers.google.com/identity/protocols/OAuth2?hl=en_US#installed) desktop applications and has been initally tested with [manual copy/paste](https://developers.google.com/identity/protocols/OAuth2InstalledApp#redirect-uri_oob-manual) (_of authorization code_) redirect method.

Going forward support for [Loopback IP redirect](https://developers.google.com/identity/protocols/OAuth2InstalledApp#redirect-uri_loopback) is planned to be added.

### Prerequisites

1. Create your application in [Google API Console](https://console.developers.google.com/apis/credentials)  
   a. `Credentials` > `Create credentials` > `OAuth client ID`  
   b. Set application type to `Other`  
   c. Enter your application name  
   d. `Download JSON` configuration of newly created application  

### Example

```rust
extern crate rust_google_oauth2 as gauth;

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
        vec![
            "https://www.googleapis.com/auth/drive.readonly".to_owned(),
        ],
        PathBuf::from("/my-google-credentials/oauth-credentials.json"),
    );

    let token = auth_client
        .access_token(handle_auth)
        .expect("failed to retrieve access token");

    println!("obtained token: {:?}", token);
}
```
