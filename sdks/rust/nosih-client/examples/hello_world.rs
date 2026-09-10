//! NOSIH Protocol Rust SDK — hello world example
//! Run: cargo run --example hello_world

use nosih_client::{RetryConfig, NosihClient, NosihClientConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = NosihClient::new(NosihClientConfig {
        gateway_url: std::env::var("NOSIH_GATEWAY_URL")
            .unwrap_or_else(|_| "http://localhost:3100".to_string()),
        api_key: std::env::var("NOSIH_API_KEY").ok(),
        retry_config: RetryConfig::default(),
    });

    println!("NOSIH Protocol Rust SDK — hello world");
    println!("Building a request via fluent API...");

    let request = client
        .request()
        .agent_id("my-agent-public-key-hex")
        .token_id("my-token-uuid")
        .resource("mcp://filesystem/readFile")
        .action("call")
        .build()
        .expect("Failed to build request");

    println!("Request ID: {}", request.request_id);
    println!("Resource:   {}", request.resource);
    println!("Action:     {}", request.action);

    // In a real deployment, this would call the live gateway:
    // let decision = client.intercept_with_retry(&request).await?;
    // println!("Decision: {:?}", decision.action);

    Ok(())
}
