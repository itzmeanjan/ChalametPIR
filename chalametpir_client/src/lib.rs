//! ChalametPIR: A Rust library implementation of the Chalamet **P**rivate **I**nformation **R**etrieval (PIR) protocol, described in <https://ia.cr/2024/092>.
//!
//! This crate provides a Rust library implementation of the ChalametPIR Client, enabling efficient and private lookup of value associated with a key, from encoded key-value database, stored PIR server-side.
//! It leverages Binary Fuse Filters for efficient indexing and storage of key-value database and LWE-based encryption for data confidentiality.
//!
//!
//! ## Features
//!
//! * **Secure Private Information Retrieval:**  Allows PIR clients to retrieve value from a PIR server without disclosing corresponding key. Server learns neither the value nor the queried key.
//! * **Error Handling:** Comprehensive error handling to catch and report issues during setup, query generation, and response processing.
//!
//! ## Usage
//!
//! This crate is designed to be used in conjunction with other crates which provides communication mechanism between PIR clients and server.
//! See examples. You'll typically interact with the `Client` struct to setup PIR client using server provided seed, hint and filter params. Also for
//! creating PIR queries and processing response received from PIR server. There is also a `Query` struct, which generally holds
//! the LWE secret vector for a specific queried key and uses it to decode server response.
//!
//!
//! Add this crate as dependency to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! chalametpir_client = "=0.6.0"
//! ```
//!
//! Then, you can use it in your code:
//!
//! ```rust
//! use chalametpir_client::{Client, SEED_BYTE_LEN};
//!
//! fn main() {
//!     // Assume seed, hint_bytes and filter_param_bytes are received from the PIR server
//!     let seed_μ = [0u8; SEED_BYTE_LEN];
//!     let hint_bytes = vec![0u8; 0];
//!     let filter_param_bytes = vec![0u8; 0];
//!
//!     match Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes) {
//!         Ok(mut client) => {
//!             let key = b"example_key";
//!             if let Ok(query) = client.query(key) {
//!                 println!("Generated query for key: {:?}", key);
//!                 // Send query to PIR server
//!                 let response = vec![0u8; 0];
//!                 if let Ok(value) = client.process_response(key, &response) {
//!                     println!("Received response {:?}", response);
//!                 }
//!             }
//!         }
//!         Err(err) => {
//!             println!("Client setup failed: {}", err);
//!         }
//!     };
//! }
//! ```
//!
//! For more see README in ChalametPIR repository @ <https://github.com/itzmeanjan/ChalametPIR>.

mod client;

pub use chalametpir_common::{error::ChalametPIRError, params::SEED_BYTE_LEN};
pub use client::{Client, Query};
