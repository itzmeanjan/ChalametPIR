pub use crate::pir_internals::params::SEED_BYTE_LEN;
use crate::pir_internals::{
    branch_opt_util,
    matrix::Matrix,
    params::{LWE_DIMENSION, SERVER_SETUP_MAX_ATTEMPT_COUNT},
};
use std::{collections::HashMap, u32};

#[derive(Clone)]
pub struct Server {
    /// This matrix is kept in transposed form to optimize memory access pattern in vector matrix multiplication of server-respond function.
    transposed_parsed_db_mat_d: Matrix,
}

impl Server {
    /// Sets up the keyword *P*rivate *I*nformation *R*etrieval scheme's server with a given Key-Value database.
    ///
    /// This function takes a database as input and generates the necessary matrices and parameters for responding to client queries.
    /// It involves several steps:
    /// 1. **Database Validation:** Checks if the number of key-value pairs in the database is a power of two and validates LWE parameters.  Returns `None` if validation fails.
    /// 2. **Matrix Generation from Database:** Creates a `Matrix` (`parsed_db_mat_d`) representing the database. Uses the `Matrix::from_kv_database` function, which might involve multiple attempts (`SERVER_SETUP_MAX_ATTEMPT_COUNT`) to generate a suitable matrix.  Returns `None` if matrix generation fails.  This also generates a `filter` object used in later stages of the PIR protocol.
    /// 3. **Public Matrix Generation:** Generates a public matrix (`pub_mat_a`) using a provided seed (`seed_μ`). The dimensions of this matrix are determined by `LWE_DIMENSION` and the number of fingerprints in the `filter`.
    /// 4. **Hint Matrix Calculation:** Computes the hint matrix (`hint_mat_m`) by multiplying the public matrix and the parsed database matrix.
    /// 5. **Serialization:** Converts the hint matrix and filter parameters into byte vectors for storage and transmission. Returns `None` if conversion fails.
    /// 6. **Transposition:** Transposes the parsed database matrix (`parsed_db_mat_d`) to optimize memory access pattern during the execution of the `respond` function.
    ///
    /// # Arguments
    ///
    /// * `mat_elem_bit_len`: The bit length of each element in the parsed DB matrix.  Affects the security parameters of the underlying LWE scheme.
    /// * `seed_μ`: The seed used for generating the public matrix.
    /// * `db`: The input database, represented as a hash map of key-value pairs. Keys and values are byte slices.
    ///
    /// Constant parameter `ARITY` can be with 3 or 4, denoting usage of a 3/ 4 -wise XOR binary fuse filter, under the hood.
    /// This choice affects client/ server computation and communication cost.
    ///
    /// # Returns
    ///
    /// An `Option` containing a tuple of the `Server` object, the serialized hint matrix bytes, and the serialized filter parameters bytes.  Returns `None` if any error occurs during setup.
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

        let pub_mat_a = unsafe { Matrix::generate_from_seed(pub_mat_a_num_rows, pub_mat_a_num_cols, seed_μ).unwrap_unchecked() };

        let hint_mat_m = unsafe { (&pub_mat_a * &parsed_db_mat_d).unwrap_unchecked() };
        let hint_bytes = hint_mat_m.to_bytes().ok()?;
        let filter_param_bytes: Vec<u8> = filter.to_bytes().ok()?;
        let transposed_parsed_db_mat_d = parsed_db_mat_d.transpose();

        Some((Server { transposed_parsed_db_mat_d }, hint_bytes, filter_param_bytes))
    }

    /// Responds to a client query.
    ///
    /// This function takes a client's query (in byte form) as input and uses the transposed database matrix to compute the response.
    /// The process involves:
    /// 1. **Query Vectorization:** Converts the query bytes into a row vector. Returns `None` if conversion fails.
    /// 2. **Vector-Matrix Multiplication:** Performs a row vector-transposed matrix multiplication of the query vector and the server's transposed database matrix. This is optimized for efficiency due to the transposition performed during server setup. Returns `None` if multiplication fails.
    /// 3. **Response Serialization:** Converts the resulting response vector into a byte vector for transmission to the client. Returns `None` if conversion fails.
    ///
    /// # Arguments
    ///
    /// * `query`: The client's query, represented as a byte slice.
    ///
    /// # Returns
    ///
    /// An `Option` containing the response as a byte vector. Returns `None` if any error occurs during response computation or serialization.
    pub fn respond(&self, query: &[u8]) -> Option<Vec<u8>> {
        let query_vector = Matrix::from_bytes(query).ok()?;
        let response_vector = query_vector.row_vector_x_transposed_matrix(&self.transposed_parsed_db_mat_d)?;

        response_vector.to_bytes().ok()
    }

    fn validate_lwe_params(mat_elem_bit_len: usize, db_entry_count: usize) -> bool {
        const Q: usize = u32::MAX as usize + 1;
        let ρ = 1usize << mat_elem_bit_len;

        Q >= (8 * ρ * ρ) * db_entry_count.isqrt()
    }
}
