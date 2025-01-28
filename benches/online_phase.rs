use chalamet_pir::{client, server};
use divan;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::{collections::HashMap, time::Duration};

fn main() {
    divan::main();
}

fn generate_random_kv_database(rng: &mut ChaCha8Rng, num_kv_pairs: usize, key_byte_len: usize, value_byte_len: usize) -> HashMap<Vec<u8>, Vec<u8>> {
    assert!(key_byte_len > 0);
    assert!(value_byte_len > 0);

    let mut kv = HashMap::with_capacity(num_kv_pairs);

    for _ in 0..num_kv_pairs {
        let mut key = vec![0u8; key_byte_len];
        let mut value = vec![0u8; value_byte_len];

        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut value);

        kv.insert(key, value);
    }

    kv
}

#[derive(Debug)]
struct DBConfig {
    db_entry_count: usize,
    mat_elem_bit_len: usize,
    key_byte_len: usize,
    value_byte_len: usize,
}

const ARGS: &[DBConfig] = &[DBConfig {
    db_entry_count: 1usize << 12,
    mat_elem_bit_len: 10,
    key_byte_len: 32,
    value_byte_len: 128,
}];
const ARITIES: [u32; 2] = [3, 4];

#[divan::bench(args = ARGS, consts = ARITIES, max_time = Duration::from_secs(300), skip_ext_time = true)]
fn client_query<const ARITY: u32>(bencher: divan::Bencher, db_config: &DBConfig) {
    let mut rng = ChaCha8Rng::from_entropy();

    let kv = generate_random_kv_database(&mut rng, db_config.db_entry_count, db_config.key_byte_len, db_config.value_byte_len);
    let kv_as_ref = kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

    let mut seed_μ = [0u8; server::SEED_BYTE_LEN];
    rng.fill_bytes(&mut seed_μ);

    let (_, hint_bytes, filter_param_bytes) = server::Server::setup::<ARITY>(db_config.mat_elem_bit_len, &seed_μ, kv_as_ref.clone()).unwrap();
    let client = client::Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).unwrap();

    let (&key, _) = kv_as_ref.iter().last().unwrap();

    bencher.with_inputs(|| client.clone()).bench_refs(|client| {
        let _ = divan::black_box(&mut *client).query(divan::black_box(key));
        client.discard_query(key);
    });
}

#[divan::bench(args = ARGS, consts = ARITIES, max_time = Duration::from_secs(300), skip_ext_time = true)]
fn server_respond<const ARITY: u32>(bencher: divan::Bencher, db_config: &DBConfig) {
    let mut rng = ChaCha8Rng::from_entropy();

    let kv = generate_random_kv_database(&mut rng, db_config.db_entry_count, db_config.key_byte_len, db_config.value_byte_len);
    let kv_as_ref = kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

    let mut seed_μ = [0u8; server::SEED_BYTE_LEN];
    rng.fill_bytes(&mut seed_μ);

    let (server, hint_bytes, filter_param_bytes) = server::Server::setup::<ARITY>(db_config.mat_elem_bit_len, &seed_μ, kv_as_ref.clone()).unwrap();
    let mut client = client::Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).unwrap();

    let (&key, _) = kv_as_ref.iter().last().unwrap();
    let query_bytes = client.query(key).unwrap();

    bencher.bench(|| divan::black_box(&server).respond(divan::black_box(&query_bytes)));
}

#[divan::bench(args = ARGS, consts = ARITIES, max_time = Duration::from_secs(300), skip_ext_time = true)]
fn client_process_response<const ARITY: u32>(bencher: divan::Bencher, db_config: &DBConfig) {
    let mut rng = ChaCha8Rng::from_entropy();

    let kv = generate_random_kv_database(&mut rng, db_config.db_entry_count, db_config.key_byte_len, db_config.value_byte_len);
    let kv_as_ref = kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

    let mut seed_μ = [0u8; server::SEED_BYTE_LEN];
    rng.fill_bytes(&mut seed_μ);

    let (server, hint_bytes, filter_param_bytes) = server::Server::setup::<ARITY>(db_config.mat_elem_bit_len, &seed_μ, kv_as_ref.clone()).unwrap();
    let mut client = client::Client::setup(&seed_μ, &hint_bytes, &filter_param_bytes).unwrap();

    let (&key, _) = kv_as_ref.iter().last().unwrap();
    let query_bytes = client.query(key).unwrap();

    let query = client.discard_query(key).unwrap();
    client.insert_query(key, query.clone());

    let response_bytes = server.respond(&query_bytes).unwrap();

    bencher.with_inputs(|| client.clone()).bench_refs(|client| {
        let _ = divan::black_box(&mut *client).process_response(divan::black_box(key), divan::black_box(&response_bytes));
        client.insert_query(key, query.clone());
    });
}
