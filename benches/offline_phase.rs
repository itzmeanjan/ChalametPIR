use chalamet_pir::server;
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

#[divan::bench(args = ARGS, consts = [3,4], max_time = Duration::from_secs(300), skip_ext_time = true)]
fn server_setup<const ARITY: u32>(bencher: divan::Bencher, db_config: &DBConfig) {
    let mut rng = ChaCha8Rng::from_entropy();

    let kv = generate_random_kv_database(&mut rng, db_config.db_entry_count, db_config.key_byte_len, db_config.value_byte_len);
    let kv_as_ref = kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

    let mut seed_μ = [0u8; server::SEED_BYTE_LEN];
    rng.fill_bytes(&mut seed_μ);

    bencher
        .with_inputs(|| (kv_as_ref.clone(), seed_μ.clone()))
        .bench_values(|(kv, seed)| server::Server::setup::<ARITY>(divan::black_box(db_config.mat_elem_bit_len), divan::black_box(&seed), divan::black_box(kv)));
}
