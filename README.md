# ChalametPIR
Simple, Practical, Single-Server Private Information Retrieval for Keyword Queries

## Overview
ChalametPIR is a very simple, stateful, single-server *P*rivate *I*nformation *R*etrieval (PIR) scheme for keyword queries,
built on top of FrodoPIR - a practical, single-server, stateful LWE -based PIR scheme and Binary Fuse Filter - an efficient probabilistic data structure.

- FrodoPIR was proposed in https://ia.cr/2022/981.
- Binary Fuse Filter was proposed in https://arxiv.org/pdf/2201.01174.
- And ChalametPIR was proposed in https://ia.cr/2024/092.

ChalametPIR allows a client to retrieve a specific value from a key-value database, stored on a server, without revealing the requested key to the server. It uses Binary Fuse Filters to encode key-value pairs in form of a matrix. And then it applies FrodoPIR on the encoded database matrix to actually retrieve values for requested keys.

The protocol has two participants:

**Server:**
* **`setup`:** Initializes the server with a seed, a key-value database, generating a public matrix, a hint matrix, and a Binary Fuse Filter (3-wise XOR or 4-wise XOR, configurable at compile time). It returns serialized representations of the hint matrix and filter parameters. This phase can be completed offline and is completely client-agnostic. But it is very compute-intensive, which is why this library allows you to offload expensive matrix multiplication and transposition to a GPU, gated behind the opt-in `gpu` feature. For large key-value databases (e.g., with >= $2^{18}$ entries), I recommend enabling the `gpu` feature, as it can significantly reduce the cost of the server-setup phase.
* **`respond`:** Processes a client's encrypted query, returning an encrypted response vector.

**Client:**
* **`setup`:** Initializes the client using the seed, serialized hint matrix and filter parameters received from the server.
* **`query`:** Generates an encrypted PIR query for a given key, which can be sent to server.
* **`process_response`:** Decrypts the server's response and extracts the requested value.

To paint a more practical picture, imagine, we have a database with $2^{20}$ (~1 million) keys s.t. each key is 32 -bytes and each value is 1024 -bytes (1kB).

**ChalametPIR Protocol Steps**

1) Server gets a 32 -bytes seed and the key-value database as input, returns a **6670248 -bytes (~6.36mB)** hint and **68 -bytes** Binary Fuse Filter parameters.
2) Client receives the seed, hint and Binary Fuse Filter parameters, sets itself up.
3) Client wants to privately look up a key in the server held key-value database, it generates an encrypted query of **4718600 -bytes (~4.5mB)**, when 3-wise XOR Binary Fuse Filter is used. If server decided to use a 4-wise XOR Binary Fuse Filter, query size would be **4521992 -bytes (~4.31mB)**. Client sends this encrypted query to server.
4) Server computes encrypted response of **3768 -bytes (~3.68kB)**, touching every single bit of the database.
5) Client receives the encrypted response and decrypts it.

We are setting up both server and client(s), on each of

Machine Type | Machine | Kernel | Compiler | Memory Read Speed
--- | --- | --- | --- | ---
(a) aarch64 server | AWS EC2 `m8g.8xlarge` | `Linux 6.8.0-1028-aws aarch64` | `rustc 1.86.0 (05f9846f8 2025-03-31)` | 28.25 GB/s
(b) x86_64 server | AWS EC2 `m7i.8xlarge` | `Linux 6.8.0-1028-aws x86_64` | `rustc 1.86.0 (05f9846f8 2025-03-31)` | 10.33 GB/s
(c) aarch64 server | AWS EC2 `r8g.8xlarge` | `Linux 6.8.0-1028-aws aarch64` | `rustc 1.86.0 (05f9846f8 2025-03-31)` | 28.25 GB/s

and this implementation of ChalametPIR is compiled with specified compiler, in `optimized` profile. See [Cargo.toml](./Cargo.toml).

> [!NOTE]
> Memory read speed is measured using `$ sysbench memory --memory-block-size=1G --memory-total-size=20G --memory-oper=read run` command.

Step | `(a)` Time Taken on `aarch64` server | `(b)` Time Taken on `x86_64` server | Ratio `a / b`
:-- | --: | --: | --:
`server_setup` | 9.62 minutes | 21.37 minutes | 0.45
`client_setup` | 9.48 seconds | 8.31 seconds | 1.14
`client_query` | 323.5 milliseconds | 2.08 seconds | 0.16
`server_respond` | 10.06 milliseconds | 14.06 milliseconds | 0.72
`client_process_response` | 9.44 microseconds | 13.96 microseconds | 0.68

So, the median bandwidth of the `server_respond` algorithm, which needs to traverse through the whole processed database, is
- (a) For `aarch64` server: 102.51 GB/s
- (b) For `x86_64` server: 73.35 GB/s

For demonstrating the effectiveness of offloading parts of the server-setup phase to a GPU, I benchmark it on AWS EC2 instance `g6e.8xlarge`, which features a NVIDIA L40S Tensor Core GPU and $3^{rd}$ generation AMD EPYC CPUs.

Number of entries in DB | Key length | Value length | `(a)` Time taken to setup PIR server on CPU | `(b)` Time taken to setup PIR server, partially offloading to GPU | Ratio `a / b`
:-- | --: | --: | --: | --: | --:
$2^{16}$ | 32B | 1kB | 19.55 seconds | 19.39 seconds | 1.0
$2^{18}$ | 32B | 1kB | 6.0 minutes | 2.23 minutes | 2.69
$2^{20}$ | 32B | 1kB | 25.89 minutes | 25.58 seconds | 60.72

For small key-value databases, it is not worth offloading server-setup to the GPU, but for databases with entries >= $2^{18}$, it is recommended to enable `gpu` feature, when GPU is available.

> [!NOTE]
> In both of above tables, I show only the median timing measurements, while the DB is encoded using a 3 -wise XOR Binary Fuse Filter. For more results, with more database configurations, see benchmarking [section](#benchmarking) below.

## Prerequisites
Rust stable toolchain; see https://rustup.rs for installation guide. MSRV for this crate is 1.85.0.

```bash
# While developing this library, I was using
$ rustc --version
rustc 1.85.1 (e71f9a9a9 2025-01-27)
```

If you plan to offload server-setup to GPU, you need to install Vulkan drivers and library for your target setup. I followed https://linux.how2shout.com/how-to-install-vulkan-on-ubuntu-24-04-or-22-04-lts-linux on Ubuntu 24.04 LTS, with Nvidia GPUs - it was easy to setup.

## Testing
The `chalametpir` library includes comprehensive tests to ensure functional correctness.

- **Property -based Tests:** Verify individual components: matrix operations (multiplication, addition), Binary Fuse Filter construction (3-wise and 4-wise XOR, including bits-per-entry (BPE) validation), and serialization/deserialization of `Matrix` and `BinaryFuseFilter`.
- **Integration Tests:** Cover end-to-end PIR protocol functionality: key-value database encoding/decoding (parameterized by database size, key/value lengths, and filter arity), and client-server interaction to verify correct value retrieval without key disclosure (tested with both 3-wise and 4-wise XOR filters).

To run the tests, go to the project's root directory and issue:

```bash
# Custom profile to make tests run faster!
# Default debug mode is too slow!
cargo test --profile test-release

# For testing if offloading to GPU works as expected.
cargo test --features gpu --profile test-release
```


## Benchmarking
Performance benchmarks are included to evaluate the efficiency of the PIR scheme. These benchmarks measure the time taken for various PIR operations.

To run the benchmarks, execute the following command from the root of the project:

```bash
# For benchmarking the online phase of the PIR, 
# you need to enable feature `mutate_internal_client_state`.
cargo bench --features mutate_internal_client_state --profile optimized

# For benchmarking only the server-setup phase, offloaded to the GPU.
cargo bench --features gpu --profile optimized --bench offline_phase -q server_setup
```

> [!WARNING]
> When benchmarking make sure you've disabled CPU frequency scaling, otherwise numbers you see can be misleading. I find https://github.com/google/benchmark/blob/b40db869/docs/reducing_variance.md helpful.

### On AWS EC2 Instance `m8g.8xlarge` (aarch64)
![chalamet-pir-on-aws-ec2-m8g.8xlarge](./bench-results/aws-ec2-m8g.8xlarge-chalamet-pir.png)

### On AWS EC2 Instance `m7i.8xlarge` (x86_64)
![chalamet-pir-on-aws-ec2-m7i.8xlarge](./bench-results/aws-ec2-m7i.8xlarge-chalamet-pir.png)

### On AWS EC2 Instance `r8g.8xlarge` (aarch64)
![chalamet-pir-on-aws-ec2-r8g.8xlarge](./bench-results/aws-ec2-r8g.8xlarge-chalamet-pir.png)

> [!NOTE]
> More about AWS EC2 instances @ https://aws.amazon.com/ec2/instance-types.

## Usage
First, add this library crate as a dependency in your Cargo.toml file.

```toml
[dependencies]
chalametpir = "=0.6.0"
# Or, if you want to offload server-setup to a GPU.
# chalametpir = { version = "=0.6.0", features = ["gpu"] }
rand = "=0.9.0"
rand_chacha = "=0.9.0"
```

Then, let's code a very simple keyword PIR scheme:

```rust
use chalametpir::{client::Client, server::Server, SEED_BYTE_LEN};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;

fn main() {
    // Example database (replace with your own)
    let mut db: HashMap<&[u8], &[u8]> = HashMap::new();
    db.insert(b"apple", b"red");
    db.insert(b"banana", b"yellow");

    // Server setup (offline phase)
    let mut rng = ChaCha8Rng::from_os_rng();
    let mut seed_μ = [0u8; SEED_BYTE_LEN]; // You'll want to generate a cryptographically secure random seed
    rng.fill_bytes(&mut seed_μ);

    let (server, hint_bytes, filter_param_bytes) = Server::setup::<3>(&seed_μ, db.clone()).expect("Server setup failed");

    // Client setup (offline phase)
    let mut client = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("Client setup failed");

    // Client query (online phase)
    let key = b"banana";
    if let Ok(query) = client.query(key) {
        // Send `query` to the server

        // Server response (online phase)
        let response = server.respond(&query).expect("Server failed to respond");

        // Client processes the response (online phase)
        if let Ok(value) = client.process_response(key, &response) {
            println!("Retrieved value: '{}'", String::from_utf8_lossy(&value)); // Should print "yellow"
        } else {
            println!("Failed to retrieve value.");
        }
    } else {
        println!("Failed to generate query.");
    }
}
```

The constant parameter `ARITY` (3 or 4) in `Server::setup` controls the type of Binary Fuse Filter used to encode the KV database, which affects size of the query vector and the encoded database dimensions, stored in-memory server-side. This implementation should allow you to run PIR queries on a KV database with at max 2^42 (~4 trillion) number of entries.

I maintain one example [program](./examples/kw_pir.rs) which demonstrates usage of the ChalametPIR API.

```bash
cargo run --example kw_pir --profile optimized
```

```bash
# Using 3-wise XOR Binary Fuse Filter
ChalametPIR:
Number of entries in Key-Value Database   : 65536
Size of each key                          : 8.0B
Size of each value                        : 4.0B
Arity of Binary Fuse Filter               : 3
Seed size                                 : 32.0B
Hint size                                 : 207.9KB
Filter parameters size                    : 68.0B
Query size                                : 304.0KB
Response size                             : 128.0B

✅ '64187' maps to 'b', in 274.995µs
⚠️ Random key '112599' is not present in DB
⚠️ Random key '108662' is not present in DB
⚠️ Random key '79395' is not present in DB
⚠️ Random key '72638' is not present in DB
⚠️ Random key '123690' is not present in DB
⚠️ Random key '69344' is not present in DB
⚠️ Random key '69155' is not present in DB
✅ '5918' maps to 'J', in 165.606µs
⚠️ Random key '128484' is not present in DB
⚠️ Random key '79290' is not present in DB
⚠️ Random key '104015' is not present in DB
⚠️ Random key '111256' is not present in DB
⚠️ Random key '124342' is not present in DB
⚠️ Random key '74982' is not present in DB
⚠️ Random key '93082' is not present in DB
✅ '32800' maps to 'b', in 233.29µs
✅ '20236' maps to 'Q', in 233.531µs
✅ '47334' maps to 'p', in 223.548µs
✅ '12225' maps to 'U', in 209.217µs

# --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---

# Using 4-wise XOR Binary Fuse Filter
ChalametPIR:
Number of entries in Key-Value Database   : 65536
Size of each key                          : 8.0B
Size of each value                        : 4.0B
Arity of Binary Fuse Filter               : 4
Seed size                                 : 32.0B
Hint size                                 : 207.9KB
Filter parameters size                    : 68.0B
Query size                                : 292.0KB
Response size                             : 128.0B

✅ '13239' maps to 'T', in 241.21µs
⚠️ Random key '112983' is not present in DB
⚠️ Random key '89821' is not present in DB
✅ '63385' maps to 'I', in 188.06µs
⚠️ Random key '123914' is not present in DB
⚠️ Random key '119919' is not present in DB
⚠️ Random key '72903' is not present in DB
⚠️ Random key '93634' is not present in DB
⚠️ Random key '68582' is not present in DB
✅ '55692' maps to 'n', in 359.112µs
⚠️ Random key '68191' is not present in DB
⚠️ Random key '92762' is not present in DB
✅ '997' maps to 'v', in 302.626µs
⚠️ Random key '123011' is not present in DB
✅ '37638' maps to 'F', in 240.428µs
⚠️ Random key '75802' is not present in DB
⚠️ Random key '80496' is not present in DB
✅ '42586' maps to 'T', in 224.29µs
✅ '25911' maps to 'u', in 250.494µs
✅ '15478' maps to 'S', in 257.656µs
```
