use std::{collections::HashMap, time::Duration};

use chalametpir_client::Client;
use chalametpir_server::Server;

use divan;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

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
    key_byte_len: usize,
    value_byte_len: usize,
}

const ARGS: &[DBConfig] = &[
    DBConfig {
        db_entry_count: 1usize << 16,
        key_byte_len: 32,
        value_byte_len: 1024,
    },
    DBConfig {
        db_entry_count: 1usize << 18,
        key_byte_len: 32,
        value_byte_len: 1024,
    },
    DBConfig {
        db_entry_count: 1usize << 20,
        key_byte_len: 32,
        value_byte_len: 1024,
    },
];
const ARITIES: [u32; 2] = [3, 4];

#[divan::bench(args = ARGS, consts = ARITIES, max_time = Duration::from_secs(300), skip_ext_time = true)]
fn server_setup<const ARITY: u32>(bencher: divan::Bencher, db_config: &DBConfig) {
    let mut rng = ChaCha8Rng::from_os_rng();

    let kv = generate_random_kv_database(&mut rng, db_config.db_entry_count, db_config.key_byte_len, db_config.value_byte_len);
    let kv_as_ref = kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

    let mut seed_μ = [0u8; chalametpir_server::SEED_BYTE_LEN];
    rng.fill_bytes(&mut seed_μ);

    bencher
        .with_inputs(|| (kv_as_ref.clone(), seed_μ))
        .bench_values(|(kv, seed)| Server::setup::<ARITY>(divan::black_box(&seed), divan::black_box(kv)));
}

#[divan::bench(args = ARGS, consts = ARITIES, max_time = Duration::from_secs(300), skip_ext_time = true)]
fn client_setup<const ARITY: u32>(bencher: divan::Bencher, db_config: &DBConfig) {
    let mut rng = ChaCha8Rng::from_os_rng();

    let kv = generate_random_kv_database(&mut rng, db_config.db_entry_count, db_config.key_byte_len, db_config.value_byte_len);
    let kv_as_ref = kv.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

    let mut seed_μ = [0u8; chalametpir_server::SEED_BYTE_LEN];
    rng.fill_bytes(&mut seed_μ);

    let (_, hint_bytes, filter_param_bytes) = Server::setup::<ARITY>(&seed_μ, kv_as_ref).expect("Server setup failed");
    bencher.bench(|| Client::setup(divan::black_box(&seed_μ), divan::black_box(&hint_bytes), divan::black_box(&filter_param_bytes)));
}
