pub use crate::pir_internals::params::SEED_BYTE_LEN;
use crate::pir_internals::{
    binary_fuse_filter::{self, BinaryFuseFilter},
    branch_opt_util,
    matrix::Matrix,
    params::LWE_DIMENSION,
    serialization,
};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Query {
    vec_c: Matrix,
}

#[derive(Clone)]
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

    #[cfg(feature = "mutate_internal_client_state")]
    #[inline(always)]
    pub fn discard_query(&mut self, key: &'a [u8]) -> Option<Query> {
        self.pending_queries.remove(key)
    }

    #[cfg(feature = "mutate_internal_client_state")]
    #[inline(always)]
    pub fn insert_query(&mut self, key: &'a [u8], query: Query) {
        self.pending_queries.insert(key, query);
    }

    pub fn query(&mut self, key: &'a [u8]) -> Option<Vec<u8>> {
        match self.filter.arity {
            3 => self.query_for_3_wise_xor_filter(key),
            4 => self.query_for_4_wise_xor_filter(key),
            _ => {
                branch_opt_util::cold();
                None
            }
        }
    }

    fn query_for_3_wise_xor_filter(&mut self, key: &'a [u8]) -> Option<Vec<u8>> {
        if branch_opt_util::unlikely(self.pending_queries.contains_key(key)) {
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
        let (h0, h1, h2) = binary_fuse_filter::hash_batch_for_3_wise_xor_filter(hash, self.filter.segment_length, self.filter.segment_count_length);

        let query_indicator = self.calculate_query_indicator();

        let (added_val, flag) = query_vec_b[(0, h0 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return None;
        } else {
            query_vec_b[(0, h0 as usize)] = added_val;
        }

        let (added_val, flag) = query_vec_b[(0, h1 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return None;
        } else {
            query_vec_b[(0, h1 as usize)] = added_val;
        }

        let (added_val, flag) = query_vec_b[(0, h2 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return None;
        } else {
            query_vec_b[(0, h2 as usize)] = added_val;
        }

        let query_bytes = query_vec_b.to_bytes().ok()?;
        self.pending_queries.insert(key, Query { vec_c: secret_vec_c });

        Some(query_bytes)
    }

    fn query_for_4_wise_xor_filter(&mut self, key: &'a [u8]) -> Option<Vec<u8>> {
        if branch_opt_util::unlikely(self.pending_queries.contains_key(key)) {
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
        let (h0, h1, h2, h3) = binary_fuse_filter::hash_batch_for_4_wise_xor_filter(hash, self.filter.segment_length, self.filter.segment_count_length);

        let query_indicator = self.calculate_query_indicator();

        let (added_val, flag) = query_vec_b[(0, h0 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return None;
        } else {
            query_vec_b[(0, h0 as usize)] = added_val;
        }

        let (added_val, flag) = query_vec_b[(0, h1 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return None;
        } else {
            query_vec_b[(0, h1 as usize)] = added_val;
        }

        let (added_val, flag) = query_vec_b[(0, h2 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return None;
        } else {
            query_vec_b[(0, h2 as usize)] = added_val;
        }

        let (added_val, flag) = query_vec_b[(0, h3 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return None;
        } else {
            query_vec_b[(0, h3 as usize)] = added_val;
        }

        let query_bytes = query_vec_b.to_bytes().ok()?;
        self.pending_queries.insert(key, Query { vec_c: secret_vec_c });

        Some(query_bytes)
    }

    pub fn process_response(&mut self, key: &'a [u8], response_bytes: &[u8]) -> Option<Vec<u8>> {
        match self.pending_queries.get(key) {
            Some(query) => {
                let secret_vec_c = &query.vec_c;

                let response_vector = Matrix::from_bytes(response_bytes).ok()?;
                if branch_opt_util::unlikely(!(response_vector.get_num_rows() == 1 && response_vector.get_num_cols() == secret_vec_c.get_num_cols())) {
                    return None;
                }

                let rounding_factor = self.calculate_query_indicator();
                let rounding_floor = rounding_factor / 2;
                let mat_elem_mask = (1u32 << self.filter.mat_elem_bit_len) - 1;

                let hashed_key = binary_fuse_filter::hash_of_key(key);
                let hash = binary_fuse_filter::mix256(&hashed_key, &self.filter.seed);

                let recovered_row = (0..response_vector.get_num_cols())
                    .map(|idx| {
                        let unscaled_res = response_vector[(0, idx)].wrapping_sub(secret_vec_c[(0, idx)]);

                        let scaled_res = unscaled_res / rounding_factor;
                        let scaled_rem = unscaled_res % rounding_factor;

                        let mut rounded_res = scaled_res;
                        if scaled_rem > rounding_floor {
                            rounded_res += 1;
                        }

                        let masked = rounded_res & mat_elem_mask;
                        let unmasked = masked.wrapping_add(binary_fuse_filter::mix(hash, idx as u64) as u32) & mat_elem_mask;

                        unmasked
                    })
                    .collect::<Vec<u32>>();

                let value = match serialization::decode_kv_from_row(&recovered_row, self.filter.mat_elem_bit_len) {
                    Some(mut decoded_kv) => {
                        let mut hashed_key_as_bytes = [0u8; 32];

                        hashed_key_as_bytes[..8].copy_from_slice(&hashed_key[0].to_le_bytes());
                        hashed_key_as_bytes[8..16].copy_from_slice(&hashed_key[1].to_le_bytes());
                        hashed_key_as_bytes[16..24].copy_from_slice(&hashed_key[2].to_le_bytes());
                        hashed_key_as_bytes[24..].copy_from_slice(&hashed_key[3].to_le_bytes());

                        if (0..hashed_key_as_bytes.len()).fold(0u8, |acc, idx| acc ^ (decoded_kv[idx] ^ hashed_key_as_bytes[idx])) == 0 {
                            decoded_kv.drain(..hashed_key_as_bytes.len());
                            Some(decoded_kv)
                        } else {
                            None
                        }
                    }
                    None => {
                        branch_opt_util::cold();
                        None
                    }
                };

                self.pending_queries.remove(key);
                value
            }
            None => {
                branch_opt_util::cold();
                None
            }
        }
    }

    const fn calculate_query_indicator(&self) -> u32 {
        const MODULUS: u64 = u32::MAX as u64 + 1;
        let plaintext_modulo = 1u64 << self.filter.mat_elem_bit_len;

        (MODULUS / plaintext_modulo) as u32
    }
}
