use chalamet_pir::{SEED_BYTE_LEN, client::Client, server::Server};
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

fn format_bytes(bytes: usize) -> String {
    let suffixes = ["B", "KB", "MB", "GB"];
    let mut index = 0;
    let mut size = bytes as f64;

    while size >= 1024.0 && index < 3 {
        size /= 1024.0;
        index += 1;
    }

    format!("{:.1}{}", size, suffixes[index])
}

fn main() {
    const ARITY: u32 = 3;

    let mut rng = ChaCha8Rng::from_os_rng();

    // Make a sample Key-Value database.
    let kv_db = make_toy_kv_db(&mut rng);
    let kv_db_as_bytes = kv_db
        .iter()
        .map(|(k, v)| (k.to_le_bytes(), v.encode_utf8(&mut [0u8; 4]).as_bytes().to_vec()))
        .collect::<HashMap<[u8; 8], Vec<u8>>>();
    let kv_db_as_ref = kv_db_as_bytes
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect::<HashMap<&[u8], &[u8]>>();

    let key_byte_len = std::mem::size_of_val(kv_db.keys().next().unwrap());
    let value_byte_len = std::mem::size_of_val(kv_db.values().next().unwrap());

    println!("ChalametPIR:");
    println!("Number of entries in Key-Value Database   : {}", kv_db.len());
    println!("Size of each key                          : {}", format_bytes(key_byte_len));
    println!("Size of each value                        : {}", format_bytes(value_byte_len));
    println!("Arity of Binary Fuse Filter               : {}", ARITY);

    // Sample seed for producing public LWE matrix A.
    let mut seed_μ = [0u8; SEED_BYTE_LEN];
    rng.fill_bytes(&mut seed_μ);

    // Setup PIR server, for given KV database.
    let (server_handle, hint_bytes, filter_param_bytes) = Server::setup::<ARITY>(&seed_μ, kv_db_as_ref.clone()).expect("Server setup failed");

    println!("Seed size                                 : {}", format_bytes(seed_μ.len()));
    println!("Hint size                                 : {}", format_bytes(hint_bytes.len()));
    println!("Filter parameters size                    : {}", format_bytes(filter_param_bytes.len()));

    // Setup a PIR client, given seed, hint bytes and filter param bytes, received from server.
    let mut client_handle = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("Client setup failed");

    // Sample n -many random valid/ invalid keys and attempt to query them using PIR scheme.
    // See if valid keys can be retrieved successfully. And absent keys can't be retrieved.

    let total_num_keys_to_be_queried = 20;
    let mut num_keys_quried = 0;
    while num_keys_quried < total_num_keys_to_be_queried {
        let random_key = rng.random_range(0..kv_db.len() * 2);
        let is_random_key_in_db = kv_db.contains_key(&random_key);

        let key_as_bytes = random_key.to_le_bytes();
        if let Ok(query) = client_handle.query(&key_as_bytes.as_slice()) {
            if num_keys_quried == 0 {
                println!("Query size                                : {}", format_bytes(query.len()));
            }

            let respond_begin = Instant::now();
            if let Ok(response) = server_handle.respond(query.as_slice()) {
                let respond_end = Instant::now();

                if num_keys_quried == 0 {
                    println!("Response size                             : {}\n", format_bytes(response.len()));
                }

                if let Ok(received_value_bytes) = client_handle.process_response(key_as_bytes.as_slice(), response.as_slice()) {
                    assert!(is_random_key_in_db);
                    let &expected_value = kv_db.get(&random_key).expect("Key must be present in the DB!");

                    let received_value = String::from_utf8_lossy(received_value_bytes.as_slice()).chars().next().unwrap();
                    if received_value == expected_value {
                        println!("✅ '{}' maps to '{}', in {:?}", random_key, received_value, (respond_end - respond_begin));
                    } else {
                        println!("🚫 Didn't receive expected value for key '{}'!", random_key);
                    }
                } else {
                    assert!(!is_random_key_in_db);
                    println!("⚠️ Random key '{}' is not present in DB", random_key);
                }
            } else {
                println!("⛔ Failed to receive a response for queried key '{}'", random_key);
            }
        } else {
            println!("⛔ Failed to prepare a query for key '{}'", random_key);
        }

        num_keys_quried += 1;
    }
}
