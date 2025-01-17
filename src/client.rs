use crate::{
    binary_fuse_filter::{self, BinaryFuseFilter},
    matrix::Matrix,
    params::{LWE_DIMENSION, SEED_BYTE_LEN},
    serialization,
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

    pub fn process_response(&mut self, key: &'a [u8], response_bytes: &[u8]) -> Option<Vec<u8>> {
        match self.pending_queries.get(key) {
            Some(query) => {
                let secret_vec_c = &query.vec_c;

                let response_vector = Matrix::from_bytes(response_bytes).ok()?;
                if response_vector.get_num_rows() == 1 && response_vector.get_num_cols() == secret_vec_c.get_num_cols() {
                    return None;
                }

                let rounding_factor = self.calculate_query_indicator();
                let rounding_floor = rounding_factor / 2;
                let plaintext_modulo = 1u32 << self.filter.mat_elem_bit_len;

                let recovered_row = (0..response_vector.get_num_cols())
                    .map(|idx| {
                        let unscaled_res = response_vector[(0, idx)].wrapping_sub(secret_vec_c[(0, idx)]);

                        let scaled_res = unscaled_res / rounding_factor;
                        let scaled_rem = unscaled_res % rounding_factor;

                        let mut rounded_res = scaled_res;
                        if scaled_rem > rounding_floor {
                            rounded_res += 1;
                        }

                        rounded_res % plaintext_modulo
                    })
                    .collect::<Vec<u32>>();

                let hashed_key = binary_fuse_filter::hash_of_key(key);

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
                    None => None,
                };

                self.pending_queries.remove(key);
                value
            }
            None => None,
        }
    }

    pub const fn calculate_query_indicator(&self) -> u32 {
        const MODULUS: u64 = u32::MAX as u64 + 1;
        let plaintext_modulo = 1u64 << self.filter.mat_elem_bit_len;

        (MODULUS / plaintext_modulo) as u32
    }
}
