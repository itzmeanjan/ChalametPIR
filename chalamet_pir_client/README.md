# ChalametPIR Client

Client Implementation of ChalametPIR: Simple, Stateful, Single-Server Private Information Retrieval for Key-Value Databases.

This crate provides the client-side implementation for the ChalametPIR protocol. It includes functionality for:

- Setting up the PIR client with parameters received from the server.
- Generating private information retrieval (PIR) queries for specific keys.
- Processing responses received from the server to recover the desired value.

Key components:

- `Client`:  The main struct for interacting with the PIR client.  It handles query generation and response processing.
- `Query`: Represents a PIR query, containing the secret vector needed to recover the value from the server's response.

## Usage Example

Add these dependencies to your `Cargo.toml`:

```toml
rand = "=0.9.1"
rand_chacha = "=0.9.0"
chalamet_pir_client = "=0.6.0"
```

```rust
use chalamet_pir_client::{Client, SEED_BYTE_LEN};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

fn main() {
    // Assume seed, hint_bytes and filter_param_bytes are received from the PIR server
    let seed_μ = [0u8; SEED_BYTE_LEN];
    let hint_bytes = vec![0u8; 0];
    let filter_param_bytes = vec![0u8; 0];

    let mut client = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("Client setup failed");

    let key = b"example_key";
    if let Ok(query) = client.query(key) {
        println!("Generated query for key: {:?}", key);

        // Send query to PIR server

        let response = vec![0u8; 0];
        if let Ok(value) = client.process_response(key, &response) {
            println!("Received response {:?}", response);
        }
    }
}
```
