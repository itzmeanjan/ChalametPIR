use crate::{
    pir_internals::{
        branch_opt_util,
        matrix::Matrix,
        params::{LWE_DIMENSION, SEED_BYTE_LEN, SERVER_SETUP_MAX_ATTEMPT_COUNT},
    },
    ChalametPIRError,
};
use std::collections::HashMap;

/// Represents the server in the Keyword Private Information Retrieval (PIR) scheme ChalametPIR.
///
/// The server stores an encoded database matrix, in transposed form, to optimize query response time.
#[derive(Clone)]
pub struct Server {
    /// This matrix is kept in transposed form to optimize memory access pattern in vector matrix multiplication of server-respond function.
    transposed_parsed_db_mat_d: Matrix,
}

impl Server {
    /// Sets up the keyword **P**rivate **I**nformation **R**etrieval scheme's server with a given Key-Value database.
    ///
    /// This function takes a database as input and generates the necessary matrices and parameters for responding to client queries.
    /// It involves several steps:
    /// 1. **Database Validation:** The database must not be empty and should have at most 2<sup>42</sup> entries.  Returns an error if validation fails.
    /// 2. **Matrix Generation from Database:** Creates a `Matrix` (`parsed_db_mat_d`) representing the database. Uses the `Matrix::from_kv_database` function, which might involve multiple attempts (`SERVER_SETUP_MAX_ATTEMPT_COUNT`) to generate a suitable matrix. Returns an error if matrix generation fails. This also generates a `filter` object used in later stages of the PIR protocol.
    /// 3. **Public Matrix Generation:** Generates a public matrix (`pub_mat_a`) using a provided seed (`seed_μ`). The dimensions of this matrix are determined by `LWE_DIMENSION` and the number of fingerprints in the `filter`.
    /// 4. **Hint Matrix Calculation:** Computes the hint matrix (`hint_mat_m`) by multiplying the public matrix and the parsed database matrix.
    /// 5. **Serialization:** Converts the hint matrix and filter parameters into byte vectors for storage and transmission. Returns an error if conversion fails.
    /// 6. **Transposition:** Transposes the parsed database matrix (`parsed_db_mat_d`) to optimize memory access patterns during execution of the `respond` function.
    ///
    /// # Arguments
    ///
    /// * `seed_μ`: The seed used for generating the public matrix.
    /// * `db`: The input database, represented as a hash map of key-value pairs.
    ///
    /// The constant parameter `ARITY` can be 3 or 4, denoting the use of a 3/4-wise XOR binary fuse filter.
    /// This choice affects client/server computation and communication costs.
    ///
    /// # Returns
    ///
    /// A `Result` containing a tuple of the `Server` object, the serialized hint matrix bytes, and the serialized filter parameters bytes. Returns an error if any error occurs during setup.
    pub fn setup<const ARITY: u32>(seed_μ: &[u8; SEED_BYTE_LEN], db: HashMap<&[u8], &[u8]>) -> Result<(Server, Vec<u8>, Vec<u8>), ChalametPIRError> {
        let db_num_kv_pairs = db.len();
        if branch_opt_util::unlikely(db_num_kv_pairs == 0) {
            return Err(ChalametPIRError::EmptyKVDatabase);
        }

        let mat_elem_bit_len = Self::find_encoded_db_matrix_element_bit_length(db_num_kv_pairs)?;
        let (parsed_db_mat_d, filter) = Matrix::from_kv_database::<ARITY>(db, mat_elem_bit_len, SERVER_SETUP_MAX_ATTEMPT_COUNT)?;

        let pub_mat_a_num_rows = LWE_DIMENSION;
        let pub_mat_a_num_cols = filter.num_fingerprints;

        let pub_mat_a = unsafe { Matrix::generate_from_seed(pub_mat_a_num_rows, pub_mat_a_num_cols, seed_μ).unwrap_unchecked() };

        let hint_mat_m = unsafe { (&pub_mat_a * &parsed_db_mat_d).unwrap_unchecked() };
        let hint_bytes = hint_mat_m.to_bytes()?;
        let filter_param_bytes: Vec<u8> = filter.to_bytes()?;
        let transposed_parsed_db_mat_d = parsed_db_mat_d.transpose();

        Ok((Server { transposed_parsed_db_mat_d }, hint_bytes, filter_param_bytes))
    }

    /// Responds to a client query.
    ///
    /// This function takes a client's query (in byte form) as input and uses the transposed database matrix to compute the response.
    /// The process involves:
    /// 1. **Query Vectorization:** Converts the query bytes into a row vector. Returns an error if conversion fails.
    /// 2. **Vector-Matrix Multiplication:** Performs a row vector-transposed matrix multiplication of the query vector and the server's transposed database matrix. This is optimized for efficiency due to the transposition performed during server setup. Returns an error if multiplication fails.
    /// 3. **Response Serialization:** Converts the resulting response vector into a byte vector for transmission to the client. Returns an error if conversion fails.
    ///
    /// # Arguments
    ///
    /// * `query`: The client's query, represented as a byte slice.
    ///
    /// # Returns
    ///
    /// A `Result` containing the response as a byte vector. Returns an error if any error occurs during response computation or serialization.
    pub fn respond(&self, query: &[u8]) -> Result<Vec<u8>, ChalametPIRError> {
        let query_vector = Matrix::from_bytes(query)?;
        let response_vector = query_vector.row_vector_x_transposed_matrix(&self.transposed_parsed_db_mat_d)?;

        response_vector.to_bytes()
    }

    /// This is required to ensure that LWE PIR protocol is correct. See eq. 8 in section 5.1 of the FrodoPIR paper @ https://ia.cr/2022/981.
    fn find_encoded_db_matrix_element_bit_length(db_entry_count: usize) -> Result<usize, ChalametPIRError> {
        const MIN_MAT_ELEM_BIT_LEN: usize = 4;
        const Q: usize = u32::MAX as usize + 1;

        let sqrt_of_num_db_entry = db_entry_count.isqrt();

        let mut mat_elem_bit_len: usize = 0;
        let mut rho = 1usize << mat_elem_bit_len;

        while Q >= (8 * rho * rho) * sqrt_of_num_db_entry {
            mat_elem_bit_len = mat_elem_bit_len.wrapping_add(1);
            rho = 1usize << mat_elem_bit_len;
        }

        mat_elem_bit_len = match mat_elem_bit_len.overflowing_sub(1) {
            (_, true) => 0,
            (wrapped, false) => wrapped,
        };

        // This should allow `db_entry_count` to be at max 2^42 (~4 trillion entries)
        if branch_opt_util::likely(mat_elem_bit_len >= MIN_MAT_ELEM_BIT_LEN) {
            Ok(mat_elem_bit_len)
        } else {
            Err(ChalametPIRError::KVDatabaseSizeTooLarge)
        }
    }
}
