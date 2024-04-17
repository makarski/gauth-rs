gauth
=====

[![CodeScene Code Health](https://codescene.io/projects/45882/status-badges/code-health)](https://codescene.io/projects/45882)

The library supports the following Google Auth flows:

* [OAuth2 for installed apps](https://developers.google.com/identity/protocols/oauth2#installed)
* [Service Accounts](https://developers.google.com/identity/protocols/oauth2/service-account)


```toml
[dependencies]
gauth = "0.8"
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
async fn main() {
    let auth_client = Auth::from_file(
        "my_credentials.json",
        vec!["https://www.googleapis.com/auth/drive"],
    )
    .unwrap();

    let token = auth_client.access_token().await.unwrap();
    println!("access token: {}", token);
}
```

It is also possible to make a **blocking call** to retrieve an access token. This may be helpful if we want to wrap the logic into a closure.

```
[dependencies]
gauth = { version = "0.8", features = ["app-blocking"] }
```

```rust,no_run
use gauth::app::Auth;

#[tokio::main]
async fn main() {
    let ga = Auth::from_file(
        "client_secret.json",
        vec!["https://www.googleapis.com/auth/drive"]
    ).unwrap();

    let closure = move || {
        // add some logic here
        ga.access_token_blocking()
    };

    let token = closure().unwrap();
    println!("token from closure: {}", token);
}
```

**Custom app name and handler**: access token will be stored in `$HOME/.{app_name}/access_token.json`

To assign a custom directory as access token caching, set env var value: `GAUTH_TOKEN_DIR`

```rust,no_run
use gauth::app::Auth;
use anyhow::Error as AnyError;

#[tokio::main]
async fn main() {
    let auth_handler = |consent_uri: String| -> Result<String, AnyError> {
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

### Bridging sync and async code

The default implementation for acquiring the access token in this library is asynchronous. However, there are scenarios where a synchronous call is necessary. For instance, asynchronous signatures can be cumbersome when used with [tonic middlewares](https://docs.rs/tonic/latest/tonic/service/trait.Interceptor.html). The difficulties of integrating synchronous and asynchronous code are outlined in this [GitHub issue](https://github.com/hyperium/tonic/issues/870).

To resolve this, we adopted an experimental approach by developing a `token_provider` package. This package includes a `Watcher` trait, which has been implemented for both the `app` and `serv_account` packages. Each implementation of this trait spawns a daemon that periodically polls for and caches token updates at specified intervals. As a result, tokens are consistently refreshed through an asynchronous process. The retrieval of tokens is simplified to a synchronous function that reads from the internal cache.

```
[dependencies]
gauth = { version = "0.8", features = ["token-watcher"] }
```

```rust,no_run
let service_account = ServiceAccount::from_file(&keypath, vec!["https://www.googleapis.com/auth/pubsub"]);

let tp = AsyncTokenProvider::new(service_account).with_interval(5);

// the token is updated every 5 seconds
// and cached in AsyncTokenProvider
tp.watch_updates().await;

// sync call to get the access token
let access_token = tp.access_token()?;
```

The full example can be found [here](./examples/async_token_provider.rs)

## License

License under either or:

* [MIT](LICENSE-MIT)
* [Apache License, Version 2.0](LICENSE-APACHE)
