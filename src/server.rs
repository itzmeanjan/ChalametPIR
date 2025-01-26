pub use crate::pir_internals::params::SEED_BYTE_LEN;
use crate::pir_internals::{
    branch_opt_util,
    matrix::Matrix,
    params::{LWE_DIMENSION, SERVER_SETUP_MAX_ATTEMPT_COUNT},
};
use std::{collections::HashMap, u32};

pub struct Server {
    parsed_db_mat_d: Matrix,
}

impl Server {
    pub fn setup<const ARITY: u32>(mat_elem_bit_len: usize, seed_μ: &[u8; SEED_BYTE_LEN], db: HashMap<&[u8], &[u8]>) -> Option<(Server, Vec<u8>, Vec<u8>)> {
        let db_num_kv_pairs = db.len();
        if branch_opt_util::unlikely(!db_num_kv_pairs.is_power_of_two()) {
            return None;
        }
        if branch_opt_util::unlikely(!Self::validate_lwe_params(mat_elem_bit_len, db_num_kv_pairs)) {
            return None;
        }

        let (parsed_db_mat_d, filter) = Matrix::from_kv_database::<ARITY>(db, mat_elem_bit_len, SERVER_SETUP_MAX_ATTEMPT_COUNT)?;

        let pub_mat_a_num_rows = LWE_DIMENSION;
        let pub_mat_a_num_cols = filter.num_fingerprints;

        let pub_mat_a = Matrix::generate_from_seed(pub_mat_a_num_rows, pub_mat_a_num_cols, seed_μ)?;

        let hint_mat_m = (&pub_mat_a * &parsed_db_mat_d)?;
        let hint_bytes = hint_mat_m.to_bytes().ok()?;
        let filter_param_bytes = filter.to_bytes().ok()?;

        Some((Server { parsed_db_mat_d }, hint_bytes, filter_param_bytes))
    }

    pub fn respond(&self, query: &[u8]) -> Option<Vec<u8>> {
        let query_vector = Matrix::from_bytes(query).ok()?;
        if branch_opt_util::unlikely(!(query_vector.get_num_rows() == 1 && query_vector.get_num_cols() == self.parsed_db_mat_d.get_num_rows())) {
            return None;
        }

        let response_vector = (&query_vector * &self.parsed_db_mat_d)?;
        response_vector.to_bytes().ok()
    }

    fn validate_lwe_params(mat_elem_bit_len: usize, db_entry_count: usize) -> bool {
        const Q: usize = u32::MAX as usize + 1;
        let ρ = 1usize << mat_elem_bit_len;

        Q >= (8 * ρ * ρ) * db_entry_count.isqrt()
    }
}
