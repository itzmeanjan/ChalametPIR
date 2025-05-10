#![cfg(test)]

use std::collections::HashMap;

use chalamet_pir_client::Client;
use chalamet_pir_common::utils::generate_random_kv_database;
use chalamet_pir_server::{ChalametPIRError, Server};

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

#[test]
fn test_keyword_pir_with_3_wise_xor_filter() {
    const ARITY: u32 = 3;

    const MIN_NUM_KV_PAIRS: usize = 1usize << 8;
    const MAX_NUM_KV_PAIRS: usize = 1usize << 16;

    let mut rng = ChaCha8Rng::from_os_rng();

    const NUM_TEST_ITERATIONS: usize = 10;
    const NUMBER_OF_PIR_QUERIES: usize = 10;

    let mut test_iter = 0;
    while test_iter < NUM_TEST_ITERATIONS {
        let num_kv_pairs_in_db = rng.random_range(MIN_NUM_KV_PAIRS..=MAX_NUM_KV_PAIRS);

        let kv_db = generate_random_kv_database(num_kv_pairs_in_db);
        let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

        let mut seed_μ = [0u8; 32];
        rng.fill_bytes(&mut seed_μ);

        let (server, hint_bytes, filter_param_bytes) = Server::setup::<ARITY>(&seed_μ, kv_db_as_ref.clone()).expect("Server setup failed");
        let mut client = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("Client setup failed");

        let all_keys = kv_db_as_ref.keys().collect::<Vec<_>>();
        let random_keys = all_keys.choose_multiple(&mut rng, NUMBER_OF_PIR_QUERIES).collect::<Vec<_>>();

        let mut kv_iter = random_keys.iter().map(|&&&k| (k, kv_db_as_ref[k]));
        let (mut key, mut value) = kv_iter.next().unwrap();
        let mut is_current_key_processed = false;

        loop {
            if is_current_key_processed {
                match kv_iter.next() {
                    Some((k, v)) => {
                        key = k;
                        value = v;
                    }
                    None => {
                        // No more KV pairs to test
                        break;
                    }
                };
            }

            match client.query(key) {
                Ok(query_bytes) => {
                    let response_bytes = server.respond(&query_bytes).expect("Server can't respond");
                    let received_value = client.process_response(key, &response_bytes).expect("Client can't extract value from response");

                    assert_eq!(value, received_value);
                    is_current_key_processed = true;
                }
                Err(e) => {
                    assert_eq!(e, ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
                    is_current_key_processed = false;
                    continue;
                }
            }
        }

        test_iter += 1;
    }
}

#[test]
fn test_keyword_pir_with_4_wise_xor_filter() {
    const ARITY: u32 = 4;

    const MIN_NUM_KV_PAIRS: usize = 1usize << 8;
    const MAX_NUM_KV_PAIRS: usize = 1usize << 16;

    let mut rng = ChaCha8Rng::from_os_rng();

    const NUM_TEST_ITERATIONS: usize = 10;
    const NUMBER_OF_PIR_QUERIES: usize = 10;

    let mut test_iter = 0;
    while test_iter < NUM_TEST_ITERATIONS {
        let num_kv_pairs_in_db = rng.random_range(MIN_NUM_KV_PAIRS..=MAX_NUM_KV_PAIRS);

        let kv_db = generate_random_kv_database(num_kv_pairs_in_db);
        let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

        let mut seed_μ = [0u8; 32];
        rng.fill_bytes(&mut seed_μ);

        let (server, hint_bytes, filter_param_bytes) = Server::setup::<ARITY>(&seed_μ, kv_db_as_ref.clone()).expect("Server setup failed");
        let mut client = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("Client setup failed");

        let all_keys = kv_db_as_ref.keys().collect::<Vec<_>>();
        let random_keys = all_keys.choose_multiple(&mut rng, NUMBER_OF_PIR_QUERIES).collect::<Vec<_>>();

        let mut kv_iter = random_keys.iter().map(|&&&k| (k, kv_db_as_ref[k]));
        let (mut key, mut value) = kv_iter.next().unwrap();
        let mut is_current_key_processed = false;

        loop {
            if is_current_key_processed {
                match kv_iter.next() {
                    Some((k, v)) => {
                        key = k;
                        value = v;
                    }
                    None => {
                        // No more KV pairs to test
                        break;
                    }
                };
            }

            match client.query(key) {
                Ok(query_bytes) => {
                    let response_bytes = server.respond(&query_bytes).expect("Server can't respond");
                    let received_value = client.process_response(key, &response_bytes).expect("Client can't extract value from response");

                    assert_eq!(value, received_value);
                    is_current_key_processed = true;
                }
                Err(e) => {
                    assert_eq!(e, ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
                    is_current_key_processed = false;
                    continue;
                }
            }
        }

        test_iter += 1;
    }
}
