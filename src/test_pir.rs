#![cfg(test)]

use crate::{client::Client, server::Server};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;

fn generate_random_kv_database(num_kv_pairs: usize) -> HashMap<Vec<u8>, Vec<u8>> {
    const KEY_BYTE_LEN: usize = 32;
    const VALUE_BYTE_LEN: usize = 64;

    let mut kv = HashMap::with_capacity(num_kv_pairs);
    let mut rng = ChaCha8Rng::from_entropy();

    for _ in 0..num_kv_pairs {
        let mut key = vec![0u8; KEY_BYTE_LEN];
        let mut value = vec![0u8; VALUE_BYTE_LEN];

        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut value);

        kv.insert(key, value);
    }

    kv
}

#[test]
fn test_keyword_pir() {
    const NUM_KV_PAIRS: usize = 2usize.pow(16);
    const MAT_ELEM_BIT_LEN: usize = 10;

    const MIN_ARITY: u32 = 3;
    const _MAX_ARITY: u32 = 4;

    let kv_db = generate_random_kv_database(NUM_KV_PAIRS);
    let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

    let mut rng = ChaCha8Rng::from_entropy();

    let mut seed_μ = [0u8; 32];
    rng.fill_bytes(&mut seed_μ);

    let (server, hint_bytes, filter_param_bytes) = Server::setup::<MIN_ARITY>(MAT_ELEM_BIT_LEN, &seed_μ, kv_db_as_ref.clone()).expect("Server setup failed");
    let mut client = Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).expect("Client setup failed");

    kv_db_as_ref.iter().take(10).for_each(|(&key, &original_value)| {
        let query_bytes = client.query(key).expect("Client can't generate query");
        let response_bytes = server.respond(&query_bytes).expect("Server can't respond");
        let received_value = client.process_response(key, &response_bytes).expect("Client can't extract value from response");

        assert_eq!(original_value, received_value);
    });
}
