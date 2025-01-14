use crate::{
    binary_fuse_filter::{self, BinaryFuseFilter},
    serialization,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use std::{
    cmp::min,
    collections::HashMap,
    ops::{Index, IndexMut, Mul},
};

pub struct Matrix {
    rows: usize,
    cols: usize,
    elems: Vec<u32>,
}

impl Matrix {
    pub fn new(rows: usize, cols: usize) -> Option<Matrix> {
        if !((rows > 0) && (cols > 0)) {
            None
        } else {
            Some(Matrix {
                rows,
                cols,
                elems: vec![0; rows * cols],
            })
        }
    }

    pub fn generate_from_seed(rows: usize, cols: usize, seed: &[u8; 32]) -> Option<Matrix> {
        let mut hasher = Shake128::default();
        hasher.update(seed);

        let mut reader = hasher.finalize_xof();

        let mut buffer = [0u8; 168];
        reader.read(&mut buffer);

        let mut mat = Matrix::new(rows, cols)?;
        let num_elems = mat.rows * mat.cols;

        let mut cur_elem_idx = 0;
        let mut buf_offset = 0;

        while cur_elem_idx < num_elems {
            let fillable_num_elems_from_buf = (buffer.len() - buf_offset) / 4;
            if fillable_num_elems_from_buf == 0 {
                reader.read(&mut buffer);
                buf_offset = 0;
            }

            let required_num_elems = num_elems - cur_elem_idx;
            let to_be_filled_num_elems = min(fillable_num_elems_from_buf, required_num_elems);

            let mut local_idx = cur_elem_idx;
            while local_idx < (cur_elem_idx + to_be_filled_num_elems) {
                mat.elems[local_idx] = u32::from_le_bytes(buffer[buf_offset..(buf_offset + 4)].try_into().unwrap());

                local_idx += 1;
                buf_offset += std::mem::size_of::<u32>();
            }

            cur_elem_idx += to_be_filled_num_elems;
        }

        Some(mat)
    }

    pub fn from_kv_database(
        db: HashMap<&[u8], &[u8]>,
        arity: u32,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Option<(Matrix, binary_fuse_filter::BinaryFuseFilter)> {
        match binary_fuse_filter::BinaryFuseFilter::construct_filter(&db, arity, mat_elem_bit_len, max_attempt_count) {
            Some((filter, reverse_order, reverse_h, hash_to_key)) => {
                const HASHED_KEY_BIT_LEN: usize = 256;

                let max_value_byte_len = db.values().map(|v| v.len()).max()?;
                let max_value_bit_len = max_value_byte_len * 8;

                let rows = filter.num_fingerprints;
                let cols: usize = (HASHED_KEY_BIT_LEN + max_value_bit_len + 8).div_ceil(mat_elem_bit_len);

                let mut mat = Matrix::new(rows, cols)?;
                let mat_elem_mask = (1u32 << mat_elem_bit_len) - 1;

                let mut h012 = [0u32; 5];

                for i in (0..filter.filter_size).rev() {
                    let hash = reverse_order[i];
                    let key = *hash_to_key.get(&hash)?;
                    let value = *db.get(key)?;

                    let (h0, h1, h2) = binary_fuse_filter::hash_batch(hash, filter.segment_length, filter.segment_count_length);

                    let found = reverse_h[i] as usize;
                    h012[0] = h0;
                    h012[1] = h1;
                    h012[2] = h2;
                    h012[3] = h012[0];
                    h012[4] = h012[1];

                    let row = serialization::encode_kv_as_row(key, value, mat_elem_bit_len, cols);

                    let mat_row_idx0 = h012[found + 0] as usize;
                    let mat_row_idx1 = h012[found + 1] as usize;
                    let mat_row_idx2 = h012[found + 2] as usize;

                    let elems = (0..cols)
                        .map(|elem_idx| {
                            let f1 = mat.elems[mat_row_idx1 * cols + elem_idx];
                            (elem_idx, row[elem_idx].wrapping_sub(f1))
                        })
                        .map(|(elem_idx, elem)| {
                            let f2 = mat.elems[mat_row_idx2 * cols + elem_idx];
                            (elem_idx, elem.wrapping_sub(f2) & mat_elem_mask)
                        })
                        .map(|(elem_idx, elem)| {
                            let mask = (binary_fuse_filter::mix(hash, elem_idx as u64) as u32) & mat_elem_mask;
                            elem.wrapping_sub(mask) & mat_elem_mask
                        })
                        .collect::<Vec<u32>>();

                    let fingerprints_begin_at = mat_row_idx0 * cols;
                    let fingerprints_end_at = fingerprints_begin_at + cols;

                    mat.elems[fingerprints_begin_at..fingerprints_end_at].copy_from_slice(&elems);
                }

                Some((mat, filter))
            }
            None => None,
        }
    }

    pub fn recover_value_from_encoded_kv_database(&self, key: &[u8], filter: &BinaryFuseFilter) -> Option<Vec<u8>> {
        let mat_elem_mask = (1u32 << filter.mat_elem_bit_len) - 1;

        let hashed_key = binary_fuse_filter::hash_of_key(key);
        let hash = binary_fuse_filter::mix256(&hashed_key, &filter.seed);

        let (h0, h1, h2) = binary_fuse_filter::hash_batch(hash, filter.segment_length, filter.segment_count_length);

        let recovered_row = (0..self.cols)
            .map(|elem_idx| (elem_idx, self.elems[h0 as usize * self.cols + elem_idx]))
            .map(|(elem_idx, elem)| (elem_idx, elem.wrapping_add(self.elems[h1 as usize * self.cols + elem_idx])))
            .map(|(elem_idx, elem)| (elem_idx, elem.wrapping_add(self.elems[h2 as usize * self.cols + elem_idx])))
            .map(|(elem_idx, elem)| elem.wrapping_add((binary_fuse_filter::mix(hash, elem_idx as u64) as u32) & mat_elem_mask) & mat_elem_mask)
            .collect::<Vec<u32>>();

        match serialization::decode_kv_from_row(&recovered_row, filter.mat_elem_bit_len) {
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
        }
    }
}

impl Index<(usize, usize)> for Matrix {
    type Output = u32;

    fn index(&self, index: (usize, usize)) -> &Self::Output {
        let (ridx, cidx) = index;
        &self.elems[ridx * self.cols + cidx]
    }
}

impl IndexMut<(usize, usize)> for Matrix {
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        let (ridx, cidx) = index;
        &mut self.elems[ridx * self.cols + cidx]
    }
}

impl Mul for Matrix {
    type Output = Option<Matrix>;

    fn mul(self, rhs: Self) -> Self::Output {
        if self.cols != rhs.rows {
            return None;
        }

        let mut res = Matrix::new(self.rows, rhs.cols)?;

        (0..self.rows).for_each(|ridx| {
            (0..self.cols).for_each(|k| {
                (0..rhs.cols).for_each(|cidx| {
                    res[(ridx, cidx)] += self[(ridx, k)] * rhs[(k, cidx)];
                });
            });
        });

        Some(res)
    }
}

#[cfg(test)]
mod test {
    use crate::matrix::Matrix;
    use rand::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use std::collections::HashMap;

    fn generate_random_kv_database(num_kv_pairs: usize) -> HashMap<Vec<u8>, Vec<u8>> {
        const KEY_BYTE_LEN: usize = 32;
        const VALUE_BYTE_LEN: usize = 256;

        let mut kv = HashMap::with_capacity(num_kv_pairs);
        let mut rng = ChaCha8Rng::from_entropy();

        for _ in 0..num_kv_pairs {
            let mut key = vec![0u8; KEY_BYTE_LEN];
            let mut value = vec![0u8; VALUE_BYTE_LEN];

            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut value);

            kv.insert(key, value);
        }

        kv
    }

    #[test]
    fn encode_kv_database_and_recover_values() {
        const MAX_FILTER_CONSTRUCTION_ATTEMPT_COUNT: usize = 100;

        const MIN_NUM_KV_PAIRS: usize = 1_000;
        const MAX_NUM_KV_PAIRS: usize = 10_000;

        const MIN_ARITY: u32 = 3;
        const MAX_ARITY: u32 = 4;

        const MIN_MAT_ELEM_BIT_LEN: usize = 7;
        const MAX_MAT_ELEM_BIT_LEN: usize = 10;

        for num_kv_pairs in (MIN_NUM_KV_PAIRS..=MAX_NUM_KV_PAIRS).step_by(100) {
            for arity in MIN_ARITY..=MAX_ARITY {
                for mat_elem_bit_len in MIN_MAT_ELEM_BIT_LEN..=MAX_MAT_ELEM_BIT_LEN {
                    let kv_db = generate_random_kv_database(num_kv_pairs);
                    let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

                    let (db_mat, filter) = Matrix::from_kv_database(kv_db_as_ref.clone(), arity, mat_elem_bit_len, MAX_FILTER_CONSTRUCTION_ATTEMPT_COUNT)
                        .expect("Must be able to encode key-value database as matrix");

                    for &key in kv_db_as_ref.keys() {
                        let expected_value = *kv_db_as_ref.get(key).expect("Value for queried key must be present");
                        let computed_value = db_mat
                            .recover_value_from_encoded_kv_database(key, &filter)
                            .expect("Must be able to recover value from encoded key-value database matrix");

                        assert_eq!(
                            expected_value, computed_value,
                            "num_kv_pairs = {}, arity = {}, mat_elem_bit_len = {}",
                            num_kv_pairs, arity, mat_elem_bit_len
                        );
                    }
                }
            }
        }
    }
}
