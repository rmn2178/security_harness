//! NOSIH Protocol — Rust client library.
//!
//! Provides typed structs for NOSIH capability tokens, policy decisions,
//! and a thin async HTTP client for the NOSIH gateway server.
//!
//! # Example
//! ```rust,no_run
//! use nosih_client::{NosihClient, NosihClientConfig, RetryConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = NosihClient::new(NosihClientConfig {
//!         gateway_url: "http://localhost:3100".to_string(),
//!         api_key: std::env::var("NOSIH_API_KEY").ok(),
//!         retry_config: RetryConfig::default(),
//!     });
//!     let status = client.health().await?;
//!     println!("Gateway status: {}", status.status);
//!     Ok(())
//! }
//! ```

pub mod builder;
pub mod client;
pub mod error;
pub mod retry;
pub mod types;

pub use builder::NosihRequestBuilder;
pub use client::{NosihClient, NosihClientConfig};
pub use error::NosihError;
pub use retry::RetryConfig;
pub use types::*;
