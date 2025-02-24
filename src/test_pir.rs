#![cfg(test)]

use crate::ChalametPIRError;
use crate::pir_internals::matrix::test::generate_random_kv_database;
use crate::{client::Client, server::Server};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use test_case::test_case;

#[test_case(2usize.pow(12); "A key-value database with power of 2 many entries")]
#[test_case(2usize.pow(12) + 1; "A key-value database with non-power of 2 many entries")]
fn test_keyword_pir_with_3_wise_xor_filter(num_kv_pairs_in_db: usize) {
    const ARITY: u32 = 3;

    let kv_db = generate_random_kv_database(num_kv_pairs_in_db);
    let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

    let mut rng = ChaCha8Rng::from_os_rng();

    let mut seed_μ = [0u8; 32];
    rng.fill_bytes(&mut seed_μ);

    let (server, hint_bytes, filter_param_bytes) = Server::setup::<ARITY>(&seed_μ, kv_db_as_ref.clone()).expect("Server setup failed");
    let mut client = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("Client setup failed");

    let mut kv_iter = kv_db_as_ref.iter();
    let (&(mut key), &(mut value)) = kv_iter.next().unwrap();
    let mut is_current_kv_pair_processed = false;

    loop {
        if is_current_kv_pair_processed {
            match kv_iter.next() {
                Some((&k, &v)) => {
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
                is_current_kv_pair_processed = true;
            }
            Err(e) => {
                assert_eq!(e, ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
                is_current_kv_pair_processed = false;
                continue;
            }
        }
    }
}

#[test_case(2usize.pow(12); "A key-value database with power of 2 many entries")]
#[test_case(2usize.pow(12) + 1; "A key-value database with non-power of 2 many entries")]
fn test_keyword_pir_with_4_wise_xor_filter(num_kv_pairs_in_db: usize) {
    const ARITY: u32 = 4;

    let kv_db = generate_random_kv_database(num_kv_pairs_in_db);
    let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

    let mut rng = ChaCha8Rng::from_os_rng();

    let mut seed_μ = [0u8; 32];
    rng.fill_bytes(&mut seed_μ);

    let (server, hint_bytes, filter_param_bytes) = Server::setup::<ARITY>(&seed_μ, kv_db_as_ref.clone()).expect("Server setup failed");
    let mut client = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("Client setup failed");

    let mut kv_iter = kv_db_as_ref.iter();
    let (&(mut key), &(mut value)) = kv_iter.next().unwrap();
    let mut is_current_kv_pair_processed = false;

    loop {
        if is_current_kv_pair_processed {
            match kv_iter.next() {
                Some((&k, &v)) => {
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
                is_current_kv_pair_processed = true;
            }
            Err(e) => {
                assert_eq!(e, ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
                is_current_kv_pair_processed = false;
                continue;
            }
        }
    }
}
