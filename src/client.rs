use crate::{
    binary_fuse_filter::BinaryFuseFilter,
    matrix::Matrix,
    params::{LWE_DIMENSION, SEED_BYTE_LEN},
};
use std::collections::HashMap;

pub enum QueryStatus {
    Prepared,
    Sent,
}

pub struct Query {
    status: QueryStatus,
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

    pub fn prepare_query(&mut self, key: &'a [u8]) -> Option<()> {
        if self.pending_queries.contains_key(key) {
            return None;
        }

        let secret_vec_num_cols = LWE_DIMENSION;
        let secret_vec_s = Matrix::sample_from_uniform_ternary_dist(1, secret_vec_num_cols)?;

        let error_vector_num_cols = self.pub_mat_a.get_num_cols();
        let error_vec_e = Matrix::sample_from_uniform_ternary_dist(1, error_vector_num_cols)?;

        let vec_b = ((&secret_vec_s * &self.pub_mat_a)? + error_vec_e)?;
        let vec_c = (&secret_vec_s * &self.hint_mat_m)?;

        self.pending_queries.insert(
            key,
            Query {
                status: QueryStatus::Prepared,
                vec_b,
                vec_c,
            },
        );

        Some(())
    }
}
