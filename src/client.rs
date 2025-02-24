use crate::{
    ChalametPIRError,
    pir_internals::{
        binary_fuse_filter::{self, BinaryFuseFilter},
        branch_opt_util,
        matrix::Matrix,
        params::{HASHED_KEY_BYTE_LEN, LWE_DIMENSION, SEED_BYTE_LEN},
        serialization,
    },
};
use std::collections::HashMap;

/// Represents a PIR query. This struct is used to store secret vector `c`, which is used to recover value from PIR server response.
#[derive(Clone)]
pub struct Query {
    vec_c: Matrix,
}

/// Represents a client, performing Chalamet Private Information Retrieval (PIR) queries.
///
/// This struct holds the necessary data and methods for setting up a PIR client, generating PIR queries, processing PIR server response, privately fetching value associated with queried key.
#[derive(Clone)]
pub struct Client {
    pub_mat_a: Matrix,
    hint_mat_m: Matrix,
    filter: BinaryFuseFilter,
    pending_queries: HashMap<Vec<u8>, Query>,
}

impl Client {
    /// Sets up a new keyword **P**rivate **I**nformation **R**etrieval client instance.
    ///
    /// This function initializes a client object with the necessary parameters for performing private information retrieval (PIR) queries.
    /// It takes as input:
    ///
    /// * `seed_μ`: A byte array representing the seed for generating the public matrix A.  The length is determined by `SEED_BYTE_LEN`.
    /// * `hint_bytes`: A byte array representing the hint matrix M. This matrix is used to help reconstruct the result of the PIR query.
    /// * `filter_param_bytes`: A byte array containing the parameters for the underlying binary fuse filter in-use.
    ///
    /// Errors can occur if the `BinaryFuseFilter` cannot be constructed from the provided bytes, or if matrix generation fails.  These errors will result in a `ChalametPIRError` being returned.
    pub fn setup(seed_μ: &[u8; SEED_BYTE_LEN], hint_bytes: &[u8], filter_param_bytes: &[u8]) -> Result<Client, ChalametPIRError> {
        let filter = BinaryFuseFilter::from_bytes(filter_param_bytes)?;

        let pub_mat_a_num_rows = LWE_DIMENSION;
        let pub_mat_a_num_cols = filter.num_fingerprints;

        let pub_mat_a = Matrix::generate_from_seed(pub_mat_a_num_rows, pub_mat_a_num_cols, seed_μ)?;
        let hint_mat_m = Matrix::from_bytes(hint_bytes)?;
        if branch_opt_util::unlikely(hint_mat_m.num_rows() != LWE_DIMENSION) {
            return Err(ChalametPIRError::InvalidHintMatrix);
        }

        Ok(Client {
            pub_mat_a,
            hint_mat_m,
            filter,
            pending_queries: HashMap::new(),
        })
    }

    /// Used only for benchmarking. You are not supposed to use this.
    #[cfg(feature = "mutate_internal_client_state")]
    #[inline(always)]
    pub fn discard_query(&mut self, key: &[u8]) -> Option<Query> {
        self.pending_queries.remove(key)
    }

    /// Used only for benchmarking. You are not supposed to use this.
    #[cfg(feature = "mutate_internal_client_state")]
    #[inline(always)]
    pub fn insert_query(&mut self, key: &[u8], query: Query) {
        self.pending_queries.insert(key.to_vec(), query);
    }

    /// Generates a PIR query for the specified key.
    ///
    /// The query is added to the client's pending queries, awaiting a response. If a query for the same key already exists, this function returns an error.
    ///
    /// # Arguments
    ///
    /// * `key`: The key to query.
    ///
    /// # Returns
    ///
    /// `Result<Vec<u8>, ChalametPIRError>` containing the query bytes if successful, or an error if a query for the same key already exists or if arithmetic overflow occurs during query generation.
    pub fn query(&mut self, key: &[u8]) -> Result<Vec<u8>, ChalametPIRError> {
        match self.filter.arity {
            3 => self.query_for_3_wise_xor_filter(key),
            4 => self.query_for_4_wise_xor_filter(key),
            _ => {
                branch_opt_util::cold();
                Err(ChalametPIRError::UnsupportedArityForBinaryFuseFilter)
            }
        }
    }

    fn query_for_3_wise_xor_filter(&mut self, key: &[u8]) -> Result<Vec<u8>, ChalametPIRError> {
        if branch_opt_util::unlikely(self.pending_queries.contains_key(key)) {
            return Err(ChalametPIRError::PendingQueryExistsForKey);
        }

        let secret_vec_num_cols = LWE_DIMENSION;
        let secret_vec_s = unsafe { Matrix::sample_from_uniform_ternary_dist(1, secret_vec_num_cols).unwrap_unchecked() };

        let error_vector_num_cols = self.pub_mat_a.num_cols();
        let error_vec_e = unsafe { Matrix::sample_from_uniform_ternary_dist(1, error_vector_num_cols).unwrap_unchecked() };

        let mut query_vec_b = unsafe { ((&secret_vec_s * &self.pub_mat_a).unwrap_unchecked() + error_vec_e).unwrap_unchecked() };
        let secret_vec_c = unsafe { (&secret_vec_s * &self.hint_mat_m).unwrap_unchecked() };

        let hashed_key = binary_fuse_filter::hash_of_key(key);
        let hash = binary_fuse_filter::mix256(&hashed_key, &self.filter.seed);
        let (h0, h1, h2) = binary_fuse_filter::hash_batch_for_3_wise_xor_filter(hash, self.filter.segment_length, self.filter.segment_count_length);

        let query_indicator = self.calculate_query_indicator();

        let (added_val, flag) = query_vec_b[(0, h0 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return Err(ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
        } else {
            query_vec_b[(0, h0 as usize)] = added_val;
        }

        let (added_val, flag) = query_vec_b[(0, h1 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return Err(ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
        } else {
            query_vec_b[(0, h1 as usize)] = added_val;
        }

        let (added_val, flag) = query_vec_b[(0, h2 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return Err(ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
        } else {
            query_vec_b[(0, h2 as usize)] = added_val;
        }

        let query_bytes = query_vec_b.to_bytes()?;
        self.pending_queries.insert(key.to_vec(), Query { vec_c: secret_vec_c });

        Ok(query_bytes)
    }

    fn query_for_4_wise_xor_filter(&mut self, key: &[u8]) -> Result<Vec<u8>, ChalametPIRError> {
        if branch_opt_util::unlikely(self.pending_queries.contains_key(key)) {
            return Err(ChalametPIRError::PendingQueryExistsForKey);
        }

        let secret_vec_num_cols = LWE_DIMENSION;
        let secret_vec_s = unsafe { Matrix::sample_from_uniform_ternary_dist(1, secret_vec_num_cols).unwrap_unchecked() };

        let error_vector_num_cols = self.pub_mat_a.num_cols();
        let error_vec_e = unsafe { Matrix::sample_from_uniform_ternary_dist(1, error_vector_num_cols).unwrap_unchecked() };

        let mut query_vec_b = unsafe { ((&secret_vec_s * &self.pub_mat_a).unwrap_unchecked() + error_vec_e).unwrap_unchecked() };
        let secret_vec_c = unsafe { (&secret_vec_s * &self.hint_mat_m).unwrap_unchecked() };

        let hashed_key = binary_fuse_filter::hash_of_key(key);
        let hash = binary_fuse_filter::mix256(&hashed_key, &self.filter.seed);
        let (h0, h1, h2, h3) = binary_fuse_filter::hash_batch_for_4_wise_xor_filter(hash, self.filter.segment_length, self.filter.segment_count_length);

        let query_indicator = self.calculate_query_indicator();

        let (added_val, flag) = query_vec_b[(0, h0 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return Err(ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
        } else {
            query_vec_b[(0, h0 as usize)] = added_val;
        }

        let (added_val, flag) = query_vec_b[(0, h1 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return Err(ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
        } else {
            query_vec_b[(0, h1 as usize)] = added_val;
        }

        let (added_val, flag) = query_vec_b[(0, h2 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return Err(ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
        } else {
            query_vec_b[(0, h2 as usize)] = added_val;
        }

        let (added_val, flag) = query_vec_b[(0, h3 as usize)].overflowing_add(query_indicator);
        if branch_opt_util::unlikely(flag) {
            return Err(ChalametPIRError::ArithmeticOverflowAddingQueryIndicator);
        } else {
            query_vec_b[(0, h3 as usize)] = added_val;
        }

        let query_bytes = query_vec_b.to_bytes()?;
        self.pending_queries.insert(key.to_vec(), Query { vec_c: secret_vec_c });

        Ok(query_bytes)
    }

    /// Processes a response to a PIR query.
    ///
    /// This function takes the key associated with a pending query and the received response bytes as input.
    /// It reconstructs the original data from the response, removes the query from the pending queries, and returns the result.
    ///
    /// # Arguments
    ///
    /// * `key`: The key associated with the query.
    /// * `response_bytes`: The bytes received as a response to the query.
    ///
    /// # Returns
    ///
    /// `Result<Vec<u8>, ChalametPIRError>` containing the retrieved data if successful, or an error if the response vector has an unexpected dimension, if decoding fails, or if the query is not found in `pending_queries`.
    pub fn process_response(&mut self, key: &[u8], response_bytes: &[u8]) -> Result<Vec<u8>, ChalametPIRError> {
        match self.pending_queries.get(key) {
            Some(query) => {
                let secret_vec_c = &query.vec_c;

                let response_vector = Matrix::from_bytes(response_bytes)?;
                if branch_opt_util::unlikely(!(response_vector.num_rows() == 1 && response_vector.num_cols() == secret_vec_c.num_cols())) {
                    return Err(ChalametPIRError::InvalidResponseVector);
                }

                let rounding_factor = self.calculate_query_indicator();
                let rounding_floor = rounding_factor / 2;
                let mat_elem_mask = (1u32 << self.filter.mat_elem_bit_len) - 1;

                let hashed_key = binary_fuse_filter::hash_of_key(key);
                let hash = binary_fuse_filter::mix256(&hashed_key, &self.filter.seed);

                let recovered_row = (0..response_vector.num_cols())
                    .map(|idx| {
                        let unscaled_res = response_vector[(0, idx)].wrapping_sub(secret_vec_c[(0, idx)]);

                        let scaled_res = unscaled_res / rounding_factor;
                        let scaled_rem = unscaled_res % rounding_factor;

                        let mut rounded_res = scaled_res;
                        if scaled_rem > rounding_floor {
                            rounded_res += 1;
                        }

                        let masked = rounded_res & mat_elem_mask;
                        masked.wrapping_add(binary_fuse_filter::mix(hash, idx as u64) as u32) & mat_elem_mask
                    })
                    .collect::<Vec<u32>>();

                let value = match serialization::decode_kv_from_row(&recovered_row, self.filter.mat_elem_bit_len) {
                    Ok(mut decoded_kv) => {
                        let mut hashed_key_as_bytes = [0u8; HASHED_KEY_BYTE_LEN];

                        hashed_key_as_bytes[..8].copy_from_slice(&hashed_key[0].to_le_bytes());
                        hashed_key_as_bytes[8..16].copy_from_slice(&hashed_key[1].to_le_bytes());
                        hashed_key_as_bytes[16..24].copy_from_slice(&hashed_key[2].to_le_bytes());
                        hashed_key_as_bytes[24..].copy_from_slice(&hashed_key[3].to_le_bytes());

                        let is_key_matching = (0..hashed_key_as_bytes.len()).fold(0u8, |acc, idx| acc ^ (decoded_kv[idx] ^ hashed_key_as_bytes[idx])) == 0;

                        if branch_opt_util::likely(is_key_matching) {
                            decoded_kv.drain(..hashed_key_as_bytes.len());
                            Ok(decoded_kv)
                        } else {
                            Err(ChalametPIRError::DecodedRowNotPrependedWithDigestOfKey)
                        }
                    }
                    Err(e) => {
                        branch_opt_util::cold();
                        Err(e)
                    }
                };

                self.pending_queries.remove(key);
                value
            }
            None => {
                branch_opt_util::cold();
                Err(ChalametPIRError::PendingQueryDoesNotExistForKey)
            }
        }
    }

    const fn calculate_query_indicator(&self) -> u32 {
        const MODULUS: u64 = u32::MAX as u64 + 1;
        let plaintext_modulo = 1u64 << self.filter.mat_elem_bit_len;

        (MODULUS / plaintext_modulo) as u32
    }
}
