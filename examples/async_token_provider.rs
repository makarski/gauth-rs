//! `RUST_LOG=DEBUG cargo run --example async_token_provider --features token-watcher path/to/service-account-key.json` to run the example
use tokio::time::{sleep, Duration};

use gauth::serv_account::ServiceAccount;
use gauth::token_provider::AsyncTokenProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let keypath = std::env::args()
        .nth(1)
        .expect("Provide a path to the service account key file");

    let service_account = ServiceAccount::from_file(&keypath)
        .unwrap()
        .scopes(vec!["https://www.googleapis.com/auth/pubsub"])
        .build()
        .unwrap();

    let tp = AsyncTokenProvider::new(service_account).with_interval(5);

    // the token is updated every 5 seconds
    // and cached in AsyncTokenProvider
    tp.watch_updates().await;

    sleep(Duration::from_secs(2)).await;

    // sync call to get the access token
    let access_token = tp.access_token()?;
    println!("\n>> Access token: {}\n", access_token);

    sleep(Duration::from_secs(30)).await;

    Ok(())
}
