use crate::{
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
    pending_queries: HashMap<&'a [u8], Query>,
}

impl<'a> Client<'a> {
    pub fn setup(seed_μ: &[u8; SEED_BYTE_LEN], pub_mat_a_num_cols: usize, hint_bytes: &[u8]) -> Option<Client<'a>> {
        let pub_mat_a_num_rows = LWE_DIMENSION;
        let pub_mat_a = Matrix::generate_from_seed(pub_mat_a_num_rows, pub_mat_a_num_cols, seed_μ)?;

        let hint_mat_m = Matrix::from_bytes(hint_bytes).ok()?;

        Some(Client {
            pub_mat_a,
            hint_mat_m,
            pending_queries: HashMap::new(),
        })
    }
}
