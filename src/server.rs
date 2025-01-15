use crate::{binary_fuse_filter::BinaryFuseFilter, matrix::Matrix};
use std::collections::HashMap;

pub const λ: usize = 128;
pub const LWE_DIMENSION: usize = 1774;
pub const SEED_BYTE_LEN: usize = (2 * λ) / 8;
pub const SERVER_SETUP_MAX_ATTEMPT_COUNT: usize = 100;

pub struct Server {
    arity: u32,
    mat_elem_bit_len: usize,
    db_num_kv_pairs: usize,
    parsed_db_mat_d: Matrix,
    filter: BinaryFuseFilter,
}

impl Server {
    pub fn setup(arity: u32, mat_elem_bit_len: usize, seed_μ: &[u8; SEED_BYTE_LEN], db: HashMap<&[u8], &[u8]>) -> Option<(Server, Vec<u8>)> {
        let db_num_kv_pairs = db.len();
        if !db_num_kv_pairs.is_power_of_two() {
            return None;
        }

        let (parsed_db_mat_d, filter) = Matrix::from_kv_database(db, arity, mat_elem_bit_len, SERVER_SETUP_MAX_ATTEMPT_COUNT)?;

        let pub_mat_a_num_rows = LWE_DIMENSION;
        let pub_mat_a_num_cols = filter.num_fingerprints;

        let pub_mat_a = Matrix::generate_from_seed(pub_mat_a_num_rows, pub_mat_a_num_cols, seed_μ)?;

        let hint_mat_m = (pub_mat_a * parsed_db_mat_d.clone())?;
        let hint_bytes = hint_mat_m.to_bytes().ok()?;

        Some((
            Server {
                arity,
                mat_elem_bit_len,
                db_num_kv_pairs,
                parsed_db_mat_d,
                filter,
            },
            hint_bytes,
        ))
    }
}
