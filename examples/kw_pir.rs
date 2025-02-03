// This program demonstrates a simple Key-Value Private Information Retrieval (PIR) scheme.
// It uses the `chalamet-pir` crate to perform the PIR operations.
// The program generates a toy Key-Value database, sets up a PIR server and client,
// and then performs queries for each key in the database, measuring response time.
// The results are printed to the console, indicating success or failure for each query.

use chalamet_pir::{client::Client, server::Server};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::time::Instant;
use unicode_xid::UnicodeXID;

/// Generates a toy Key-Value database with a specified number of entries.
/// Each key is a usize, and each value is a randomly chosen Unicode character
/// that is either ASCII graphic, alphanumeric, and a valid Unicode identifier start.
///
/// # Arguments
///
/// * `rng` - A mutable reference to a ChaCha8Rng random number generator.  This is used to generate random values.
///
/// # Returns
///
/// A HashMap containing the generated Key-Value pairs.
fn make_toy_kv_db(rng: &mut ChaCha8Rng) -> HashMap<usize, char> {
    const NUM_DB_ENTRIES: usize = u16::MAX as usize + 1;

    (0..NUM_DB_ENTRIES)
        .map(|db_entry_index| {
            let c = loop {
                let mut buf = [0u8; 4];
                rng.fill_bytes(&mut buf);

                let s = String::from_utf8_lossy(&buf);
                if let Some(c) = s.chars().next() {
                    if (c.is_ascii_graphic() || c.is_alphanumeric()) && c.is_xid_start() {
                        break c;
                    }
                }
            };

            (db_entry_index, c)
        })
        .collect::<HashMap<usize, char>>()
}

fn main() {
    const MAT_ELEM_BIT_LEN: usize = 10;
    const ARITY: u32 = 3;

    let mut rng = ChaCha8Rng::from_entropy();

    // Make sample Key-Value database.
    let kv_db = make_toy_kv_db(&mut rng);
    let kv_db_as_bytes = kv_db
        .iter()
        .map(|(k, v)| (k.to_le_bytes(), v.encode_utf8(&mut [0u8; 4]).as_bytes().to_vec()))
        .collect::<HashMap<[u8; 8], Vec<u8>>>();
    let kv_db_as_ref = kv_db_as_bytes
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect::<HashMap<&[u8], &[u8]>>();

    // Sample seed for producing public LWE matrix A.
    let mut seed_μ = [0u8; 32];
    rng.fill_bytes(&mut seed_μ);

    // Setup PIR server, for given KV database.
    let (server_handle, hint_bytes, filter_param_bytes) = Server::setup::<ARITY>(MAT_ELEM_BIT_LEN, &seed_μ, kv_db_as_ref.clone()).expect("Server setup failed");

    // Setup a PIR client, given seed, hint bytes and filter param bytes, received from server.
    let mut client_handle = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("Client setup failed");

    for (key, expected_value) in kv_db {
        let key_as_bytes = key.to_le_bytes();
        if let Some(query) = client_handle.query(&key_as_bytes.as_slice()) {
            let respond_begin = Instant::now();
            if let Some(response) = server_handle.respond(query.as_slice()) {
                let respond_end = Instant::now();

                if let Some(received_value_bytes) = client_handle.process_response(key_as_bytes.as_slice(), response.as_slice()) {
                    let received_value = String::from_utf8_lossy(received_value_bytes.as_slice()).chars().next().unwrap();
                    if received_value == expected_value {
                        println!("✅ {} => {}, in {:?}", key, received_value, (respond_end - respond_begin));
                    } else {
                        println!(
                            "⚠️⚠️⚠️ Received value '{}' does not match expected value '{}' for key '{}'",
                            received_value, expected_value, key
                        );
                    }
                } else {
                    println!("⛔ Failed to decode the response for queried key '{}'", key);
                }
            } else {
                println!("⛔ Failed to receive a response for queried key '{}'", key);
            }
        } else {
            println!("⛔ Failed to prepare a query for key '{}'", key);
        }
    }
}
