//! ChalametPIR: A Rust library implementation of the Chalamet **P**rivate **I**nformation **R**etrieval (PIR) protocol, described in <https://ia.cr/2024/092>.
//!
//! This crate provides a Rust library implementation of the ChalametPIR protocol, enabling efficient and private retrieval of value associated with a key, from encoded key-value database, stored server-side.
//! It leverages Binary Fuse Filters for efficient indexing and storage of key-value database and LWE-based encryption for data confidentiality.
//!
//! ## Features
//!
//! * **Secure Private Information Retrieval:**  Allows clients to retrieve value from a PIR server without disclosing corresponding key. Server learns neither the value nor the queried key.
//! * **Error Handling:** Comprehensive error handling to catch and report issues during setup, query generation, and response processing.
//! * **Flexibility:** Supports both 3-wise and 4-wise XOR Binary Fuse Filters, allowing a choice between trade-offs in client/server computation and communication costs.
//!
//! ## Usage
//!
//! This crate is designed to be used in conjunction with other crates which provides communication mechanism between clients and server.
//! You'll typically interact with the `Client` and `Server` structs to perform/ handle queries and process responses.
//!
//! Add ChalametPIR as dependency to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! chalametpir = "=0.2.0"
//! rand = "=0.9.0"
//! rand_chacha = "=0.9.0"
//! ```
//!
//! Then, you can use it in your code:
//!
//! ```rust
//! use chalamet_pir::{client::Client, server::Server, SEED_BYTE_LEN};
//! use rand::prelude::*;
//! use rand_chacha::ChaCha8Rng;
//! use std::collections::HashMap;
//!
//! fn main() {
//!     // Example database (replace with your own)
//!     let mut db: HashMap<&[u8], &[u8]> = HashMap::new();
//!     db.insert(b"apple", b"red");
//!     db.insert(b"banana", b"yellow");
//!
//!     // Server setup (offline phase)
//!     let mut rng = ChaCha8Rng::from_os_rng();
//!     let mut seed_μ = [0u8; SEED_BYTE_LEN]; // You'll want to generate a cryptographically secure random seed
//!     rng.fill_bytes(&mut seed_μ);
//!
//!     let (server, hint_bytes, filter_param_bytes) = Server::setup::<3>(&seed_μ, db.clone()).expect("Server setup failed");
//!
//!     // Client setup (offline phase)
//!     let mut client = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("Client setup failed");
//!
//!     // Client query (online phase)
//!     let key = b"banana";
//!     if let Ok(query) = client.query(key) {
//!         // Send `query` to the server
//!
//!         // Server response (online phase)
//!         let response = server.respond(&query).expect("Server failed to respond");
//!
//!         // Client processes the response (online phase)
//!         if let Ok(value) = client.process_response(key, &response) {
//!             println!("Retrieved value: '{}'", String::from_utf8_lossy(&value)); // Should print "yellow"
//!         } else {
//!             println!("Failed to retrieve value.");
//!         }
//!     } else {
//!         println!("Failed to generate query.");
//!     }
//! }
//! ```
//!
//! ## Modules
//!
//! * `server`: Contains the `Server` struct and associated methods for setting up a PIR server from a key-value database and responding to client queries.
//! * `client`: Contains the `Client` struct and associated methods for generating PIR queries and decoding server responses.
//!
//! For more see README in ChalametPIR repository @ <https://github.com/itzmeanjan/ChalametPIR>.

pub use pir_internals::error::ChalametPIRError;
pub use pir_internals::params::SEED_BYTE_LEN;
pub mod client;
pub mod server;

mod pir_internals;

mod test_pir;
