use crate::{
    binary_fuse_filter::{self, BinaryFuseFilter},
    matrix::Matrix,
    params::{LWE_DIMENSION, SEED_BYTE_LEN},
};
use std::collections::HashMap;

pub struct Query {
    vec_b: Matrix,
    vec_c: Matrix,
}

pub struct Client<'a> {
    pub_mat_a: Matrix,
    hint_mat_m: Matrix,
    filter: BinaryFuseFilter,
    pending_queries: HashMap<&'a [u8], Query>,
}

impl<'a> Client<'a> {
    pub fn setup(seed_μ: &[u8; SEED_BYTE_LEN], hint_bytes: &[u8], filter_param_bytes: &[u8]) -> Option<Client<'a>> {
        let filter = BinaryFuseFilter::from_bytes(filter_param_bytes).ok()?;

        let pub_mat_a_num_rows = LWE_DIMENSION;
        let pub_mat_a_num_cols = filter.num_fingerprints;

        let pub_mat_a = Matrix::generate_from_seed(pub_mat_a_num_rows, pub_mat_a_num_cols, seed_μ)?;

        let hint_mat_m = Matrix::from_bytes(hint_bytes).ok()?;

        Some(Client {
            pub_mat_a,
            hint_mat_m,
            filter,
            pending_queries: HashMap::new(),
        })
    }

    pub fn query(&mut self, key: &'a [u8]) -> Option<Vec<u8>> {
        if self.pending_queries.contains_key(key) {
            return None;
        }

        let secret_vec_num_cols = LWE_DIMENSION;
        let secret_vec_s = Matrix::sample_from_uniform_ternary_dist(1, secret_vec_num_cols)?;

        let error_vector_num_cols = self.pub_mat_a.get_num_cols();
        let error_vec_e = Matrix::sample_from_uniform_ternary_dist(1, error_vector_num_cols)?;

        let mut query_vec_b = ((&secret_vec_s * &self.pub_mat_a)? + error_vec_e)?;
        let secret_vec_c = (&secret_vec_s * &self.hint_mat_m)?;

        let hashed_key = binary_fuse_filter::hash_of_key(key);
        let hash = binary_fuse_filter::mix256(&hashed_key, &self.filter.seed);
        let (h0, h1, h2) = binary_fuse_filter::hash_batch(hash, self.filter.segment_length, self.filter.segment_count_length);

        let query_indicator = self.calculate_query_indicator();

        let (added_val, flag) = query_vec_b[(0, h0 as usize)].overflowing_add(query_indicator);
        if flag {
            return None;
        }
        query_vec_b[(0, h0 as usize)] = added_val;

        let (added_val, flag) = query_vec_b[(0, h1 as usize)].overflowing_add(query_indicator);
        if flag {
            return None;
        }
        query_vec_b[(0, h1 as usize)] = added_val;

        let (added_val, flag) = query_vec_b[(0, h2 as usize)].overflowing_add(query_indicator);
        if flag {
            return None;
        }
        query_vec_b[(0, h2 as usize)] = added_val;

        let query_bytes = query_vec_b.to_bytes().ok()?;
        self.pending_queries.insert(
            key,
            Query {
                vec_b: query_vec_b,
                vec_c: secret_vec_c,
            },
        );

        Some(query_bytes)
    }

    pub const fn calculate_query_indicator(&self) -> u32 {
        const MODULUS: u64 = u32::MAX as u64 + 1;
        let plaintext_modulo = 1u64 << self.filter.mat_elem_bit_len;

        (MODULUS / plaintext_modulo) as u32
    }
}
