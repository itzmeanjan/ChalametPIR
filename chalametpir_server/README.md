# ChalametPIR Server

Server Implementation of ChalametPIR: Simple, Stateful, Single-Server Private Information Retrieval for Key-Value Databases.

This crate provides the server-side implementation for the ChalametPIR protocol. It includes functionality for:

- Setting up the PIR server with a key-value database.
- Responding to PIR queries from clients s.t. the server itself doesn't learn what the client looked up.

Key components:

- `Server`: The main struct for handling PIR requests. It contains the encoded database and methods for responding to client queries.

## Usage Example

Add these dependencies to your `Cargo.toml`:

```toml
rand = "=0.9.1"
rand_chacha = "=0.9.0"
chalametpir_server = "=0.7.0"
```

```rust
use std::collections::HashMap;

use chalametpir_server::{SEED_BYTE_LEN, Server};

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

fn main() {
    // Can be either 3 or 4, denoting usage of 3-wise or 4-wise xor binary fuse filter for PIR server setup.
    const ARITY: u32 = 3;

    let mut rng = ChaCha8Rng::from_os_rng();
    let mut seed_μ = [0u8; SEED_BYTE_LEN];
    rng.fill_bytes(&mut seed_μ);

    let mut db: HashMap<&[u8], &[u8]> = HashMap::new();
    db.insert(b"key1", b"value1");
    db.insert(b"key2", b"value2");

    let (server, hint_bytes, filter_param_bytes) = Server::setup::<ARITY>(&seed_μ, db).expect("Server setup failed");

    // Start handling client PIR queries
    loop {
        // First send seed, hint and filter params to PIR client
        // so that it can set itself up.

        // Assume query_bytes is received from the client
        let query_bytes = vec![0u8; 0];

        if let Ok(response) = server.respond(&query_bytes) {
            // Send the response to the client...
            println!("Generated response of size: {} bytes", response.len());
        }
        
        break;
    }
}
```

> [!IMPORTANT]
> This crate allows you to offload compute-heavy server-setup phase to a GPU, if you enable `gpu` feature.

> [!NOTE]
> More documentation on ChalametPIR [here](../README.md).
