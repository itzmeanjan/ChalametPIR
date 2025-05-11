//! ChalametPIR: A Rust library implementation of the Chalamet **P**rivate **I**nformation **R**etrieval (PIR) protocol, described in <https://ia.cr/2024/092>.
//!
//! This crate provides a Rust library implementation of the ChalametPIR Server, enabling efficient and private retrieval of value associated with a key, from encoded key-value database, stored server-side.
//! It leverages Binary Fuse Filters for efficient indexing and storage of key-value database and LWE-based encryption for data confidentiality.
//!
//!
//! ## Features
//!
//! * **Secure Private Information Retrieval:**  Allows clients to retrieve value from a PIR server without disclosing corresponding key. Server learns neither the value nor the queried key.
//! * **Error Handling:** Comprehensive error handling to catch and report issues during setup and responding to client queries.
//! * **Flexibility:** Supports both 3-wise and 4-wise XOR Binary Fuse Filters, allowing a choice between trade-offs in client/server computation and communication costs.
//! * **Efficient:** It supports offloading parts of the server-setup phase to a GPU, using Vulkan Compute API, which can drastically reduce time taken to setup PIR server, for large key-value databases. Look for `gpu` feature.
//!
//! ## Usage
//!
//! This crate is designed to be used in conjunction with other crates which provides communication mechanism between PIR clients and server.
//! See examples. You'll typically interact with the `Server` struct to setup PIR server from a key-value database and respond to PIR client queries.
//!
//! Add this crate as dependency to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! chalametpir_server = "=0.7.0"
//! # Or, if you want to offload server-setup to GPU.
//! # chalametpir_server = { version = "=0.7.0", features = ["gpu"] }
//!
//! rand = "=0.9.1"
//! rand_chacha = "=0.9.0"
//! ```
//!
//! Then, you can use it in your code:
//!
//! ```rust
//! use std::collections::HashMap;
//!
//! use chalametpir_server::{SEED_BYTE_LEN, Server};
//!
//! use rand::prelude::*;
//! use rand_chacha::ChaCha8Rng;
//!
//! fn main() {
//!     // Can be either 3 or 4, denoting usage of 3-wise or 4-wise xor binary fuse filter for PIR server setup.
//!     const ARITY: u32 = 3;
//!
//!     let mut rng = ChaCha8Rng::from_os_rng();
//!     let mut seed_μ = [0u8; SEED_BYTE_LEN];
//!     rng.fill_bytes(&mut seed_μ);
//!
//!     let mut db: HashMap<&[u8], &[u8]> = HashMap::new();
//!     db.insert(b"key1", b"value1");
//!     db.insert(b"key2", b"value2");
//!
//!     let (server, hint_bytes, filter_param_bytes) = Server::setup::<ARITY>(&seed_μ, db).expect("Server setup failed");
//!
//!     // Start handling client PIR queries
//!     loop {
//!         // First send seed, hint and filter params to PIR client
//!         // so that it can set itself up.
//!
//!         // Assume query_bytes is received from the client
//!         let query_bytes = vec![0u8; 0];
//!
//!         if let Ok(response) = server.respond(&query_bytes) {
//!             // Send the response to the client...
//!             println!("Generated response of size: {} bytes", response.len());
//!         }
//!         
//!         break;
//!     }
//! }
//! ```
//!
//! For more see README in ChalametPIR repository @ <https://github.com/itzmeanjan/ChalametPIR>.

#[cfg(feature = "gpu")]
mod gpu;

mod server;

pub use chalametpir_common::{error::ChalametPIRError, params::SEED_BYTE_LEN};
pub use server::Server;
