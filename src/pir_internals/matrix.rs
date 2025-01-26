use crate::pir_internals::{
    binary_fuse_filter::{self},
    branch_opt_util, serialization,
};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use std::{
    cmp::min,
    collections::HashMap,
    ops::{Add, Index, IndexMut, Mul, Sub},
};

#[cfg(test)]
use std::ops::Neg;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Matrix {
    pub rows: usize,
    pub cols: usize,
    pub elems: Vec<u32>,
}

impl Matrix {
    pub fn new(rows: usize, cols: usize) -> Option<Matrix> {
        if branch_opt_util::unlikely(!((rows > 0) && (cols > 0))) {
            None
        } else {
            Some(Matrix {
                rows,
                cols,
                elems: vec![0; rows * cols],
            })
        }
    }
    pub fn from_values(rows: usize, cols: usize, values: Vec<u32>) -> Option<Matrix> {
        if branch_opt_util::unlikely(!((rows > 0) && (cols > 0))) {
            None
        } else {
            if branch_opt_util::unlikely(rows * cols != values.len()) {
                None
            } else {
                Some(Matrix { rows, cols, elems: values })
            }
        }
    }

    pub const fn get_num_rows(&self) -> usize {
        self.rows
    }
    pub const fn get_num_cols(&self) -> usize {
        self.cols
    }
    pub fn get_num_elems(&self) -> usize {
        self.elems.len()
    }

    #[inline]
    pub fn is_square(&self) -> bool {
        return self.rows == self.cols;
    }

    pub fn identity(rows: usize) -> Option<Matrix> {
        let mut mat = Matrix::new(rows, rows)?;

        (0..rows).for_each(|idx| {
            mat[(idx, idx)] = 1;
        });

        Some(mat)
    }

    pub fn transpose(&self) -> Option<Matrix> {
        let mut res = Matrix::new(self.cols, self.rows)?;

        (0..self.cols)
            .map(|ridx| (0..self.rows).map(move |cidx| (ridx, cidx)))
            .flatten()
            .for_each(|(ridx, cidx)| {
                res[(ridx, cidx)] = self[(cidx, ridx)];
            });

        Some(res)
    }

    pub fn pad(&self, n: usize) -> Matrix {
        if n <= self.rows && n <= self.cols {
            self.clone()
        } else {
            let mut values = Vec::<u32>::with_capacity(n * n);

            for i in 0..self.rows {
                (0..self.cols).for_each(|j| values.push(self[(i, j)]));
                (self.cols..n).for_each(|_| values.push(0));
            }

            for _ in self.rows..n {
                (0..n).for_each(|_| values.push(0));
            }

            Matrix::from_values(n, n, values).expect("Padding matrix must not fail")
        }
    }

    fn reduce(&self, rows: usize, cols: usize) -> Option<Matrix> {
        if rows > self.rows || cols > self.cols {
            return None;
        }

        let mut values = Vec::<u32>::with_capacity(rows * cols);

        (0..rows).for_each(|row_idx| {
            let row_offset = row_idx * self.cols;
            values.extend_from_slice(&self.elems[row_offset..(row_offset + cols)])
        });

        return Matrix::from_values(rows, cols, values);
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
            while branch_opt_util::likely(local_idx < (cur_elem_idx + to_be_filled_num_elems)) {
                mat.elems[local_idx] = u32::from_le_bytes(buffer[buf_offset..(buf_offset + 4)].try_into().unwrap());

                local_idx += 1;
                buf_offset += std::mem::size_of::<u32>();
            }

            cur_elem_idx += to_be_filled_num_elems;
        }

        Some(mat)
    }

    pub fn sample_from_uniform_ternary_dist(rows: usize, cols: usize) -> Option<Matrix> {
        if branch_opt_util::unlikely(!(rows == 1 || cols == 1)) {
            return None;
        }

        const TERNARY_INTERVAL_SIZE: u32 = (u32::MAX - 2) / 3;
        const TERNARY_REJECTION_SAMPLING_MAX: u32 = TERNARY_INTERVAL_SIZE * 3;

        let mut rng = ChaCha8Rng::from_entropy();
        let mut vec = Matrix::new(rows, cols)?;

        let num_elems = rows * cols;
        let mut elem_idx = 0;

        while branch_opt_util::likely(elem_idx < num_elems) {
            let mut val = u32::MAX;

            while branch_opt_util::unlikely(val > TERNARY_REJECTION_SAMPLING_MAX) {
                val = rng.gen::<u32>();
            }

            let ternary = if val <= TERNARY_INTERVAL_SIZE {
                0
            } else if val > TERNARY_INTERVAL_SIZE && val <= 2 * TERNARY_INTERVAL_SIZE {
                1
            } else {
                u32::MAX
            };

            vec.elems[elem_idx] = ternary;
            elem_idx += 1;
        }

        Some(vec)
    }

    pub fn from_kv_database<const ARITY: u32>(
        db: HashMap<&[u8], &[u8]>,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Option<(Matrix, binary_fuse_filter::BinaryFuseFilter)> {
        const { assert!(ARITY == 3 || ARITY == 4) }

        match ARITY {
            3 => Self::from_kv_database_with_3_wise_xor_filter(db, mat_elem_bit_len, max_attempt_count),
            4 => Self::from_kv_database_with_4_wise_xor_filter(db, mat_elem_bit_len, max_attempt_count),
            _ => {
                branch_opt_util::cold();
                panic!("Unsupported arity requested for underlying Binary Fuse Filter !")
            }
        }
    }

    #[cfg(test)]
    fn recover_value_from_encoded_kv_database<const ARITY: u32>(&self, key: &[u8], filter: &binary_fuse_filter::BinaryFuseFilter) -> Option<Vec<u8>> {
        const { assert!(ARITY == 3 || ARITY == 4) }

        match ARITY {
            3 => self.recover_value_from_3_wise_xor_filter(key, filter),
            4 => self.recover_value_from_4_wise_xor_filter(key, filter),
            _ => {
                branch_opt_util::cold();
                panic!("Unsupported arity requested for underlying Binary Fuse Filter !")
            }
        }
    }

    fn from_kv_database_with_3_wise_xor_filter(
        db: HashMap<&[u8], &[u8]>,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Option<(Matrix, binary_fuse_filter::BinaryFuseFilter)> {
        match binary_fuse_filter::BinaryFuseFilter::construct_3_wise_xor_filter(&db, mat_elem_bit_len, max_attempt_count) {
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

                    let (h0, h1, h2) = binary_fuse_filter::hash_batch_for_3_wise_xor_filter(hash, filter.segment_length, filter.segment_count_length);

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
            None => {
                branch_opt_util::cold();
                None
            }
        }
    }

    #[cfg(test)]
    fn recover_value_from_3_wise_xor_filter(&self, key: &[u8], filter: &binary_fuse_filter::BinaryFuseFilter) -> Option<Vec<u8>> {
        let mat_elem_mask = (1u32 << filter.mat_elem_bit_len) - 1;

        let hashed_key = binary_fuse_filter::hash_of_key(key);
        let hash = binary_fuse_filter::mix256(&hashed_key, &filter.seed);

        let (h0, h1, h2) = binary_fuse_filter::hash_batch_for_3_wise_xor_filter(hash, filter.segment_length, filter.segment_count_length);

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

                if branch_opt_util::likely((0..hashed_key_as_bytes.len()).fold(0u8, |acc, idx| acc ^ (decoded_kv[idx] ^ hashed_key_as_bytes[idx])) == 0) {
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
        }
    }

    fn from_kv_database_with_4_wise_xor_filter(
        db: HashMap<&[u8], &[u8]>,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Option<(Matrix, binary_fuse_filter::BinaryFuseFilter)> {
        match binary_fuse_filter::BinaryFuseFilter::construct_4_wise_xor_filter(&db, mat_elem_bit_len, max_attempt_count) {
            Some((filter, reverse_order, reverse_h, hash_to_key)) => {
                const HASHED_KEY_BIT_LEN: usize = 256;

                let max_value_byte_len = db.values().map(|v| v.len()).max()?;
                let max_value_bit_len = max_value_byte_len * 8;

                let rows = filter.num_fingerprints;
                let cols: usize = (HASHED_KEY_BIT_LEN + max_value_bit_len + 8).div_ceil(mat_elem_bit_len);

                let mut mat = Matrix::new(rows, cols)?;
                let mat_elem_mask = (1u32 << mat_elem_bit_len) - 1;

                let mut h0123 = [0u32; 7];

                for i in (0..filter.filter_size).rev() {
                    let hash = reverse_order[i];
                    let key = *hash_to_key.get(&hash)?;
                    let value = *db.get(key)?;

                    let (h0, h1, h2, h3) = binary_fuse_filter::hash_batch_for_4_wise_xor_filter(hash, filter.segment_length, filter.segment_count_length);

                    let found = reverse_h[i] as usize;
                    h0123[0] = h0;
                    h0123[1] = h1;
                    h0123[2] = h2;
                    h0123[3] = h3;
                    h0123[4] = h0123[0];
                    h0123[5] = h0123[1];
                    h0123[6] = h0123[2];

                    let row = serialization::encode_kv_as_row(key, value, mat_elem_bit_len, cols);

                    let mat_row_idx0 = h0123[found + 0] as usize;
                    let mat_row_idx1 = h0123[found + 1] as usize;
                    let mat_row_idx2 = h0123[found + 2] as usize;
                    let mat_row_idx3 = h0123[found + 3] as usize;

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
                            let f2 = mat.elems[mat_row_idx3 * cols + elem_idx];
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
            None => {
                branch_opt_util::cold();
                None
            }
        }
    }

    #[cfg(test)]
    fn recover_value_from_4_wise_xor_filter(&self, key: &[u8], filter: &binary_fuse_filter::BinaryFuseFilter) -> Option<Vec<u8>> {
        let mat_elem_mask = (1u32 << filter.mat_elem_bit_len) - 1;

        let hashed_key = binary_fuse_filter::hash_of_key(key);
        let hash = binary_fuse_filter::mix256(&hashed_key, &filter.seed);

        let (h0, h1, h2, h3) = binary_fuse_filter::hash_batch_for_4_wise_xor_filter(hash, filter.segment_length, filter.segment_count_length);

        let recovered_row = (0..self.cols)
            .map(|elem_idx| (elem_idx, self.elems[h0 as usize * self.cols + elem_idx]))
            .map(|(elem_idx, elem)| (elem_idx, elem.wrapping_add(self.elems[h1 as usize * self.cols + elem_idx])))
            .map(|(elem_idx, elem)| (elem_idx, elem.wrapping_add(self.elems[h2 as usize * self.cols + elem_idx])))
            .map(|(elem_idx, elem)| (elem_idx, elem.wrapping_add(self.elems[h3 as usize * self.cols + elem_idx])))
            .map(|(elem_idx, elem)| elem.wrapping_add((binary_fuse_filter::mix(hash, elem_idx as u64) as u32) & mat_elem_mask) & mat_elem_mask)
            .collect::<Vec<u32>>();

        match serialization::decode_kv_from_row(&recovered_row, filter.mat_elem_bit_len) {
            Some(mut decoded_kv) => {
                let mut hashed_key_as_bytes = [0u8; 32];

                hashed_key_as_bytes[..8].copy_from_slice(&hashed_key[0].to_le_bytes());
                hashed_key_as_bytes[8..16].copy_from_slice(&hashed_key[1].to_le_bytes());
                hashed_key_as_bytes[16..24].copy_from_slice(&hashed_key[2].to_le_bytes());
                hashed_key_as_bytes[24..].copy_from_slice(&hashed_key[3].to_le_bytes());

                if branch_opt_util::likely((0..hashed_key_as_bytes.len()).fold(0u8, |acc, idx| acc ^ (decoded_kv[idx] ^ hashed_key_as_bytes[idx])) == 0) {
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
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(&self).map_err(|err| format!("Failed to serialize: {}", err))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Matrix, String> {
        bincode::deserialize(bytes).map_or_else(
            |e| Err(format!("Failed to deserialize: {}", e)),
            |v: Matrix| {
                let expected_num_elems = v.get_num_rows() * v.get_num_cols();
                let actual_num_elems = v.get_num_elems();

                if branch_opt_util::likely(expected_num_elems == actual_num_elems) {
                    Ok(v)
                } else {
                    Err("Number of rows/ cols and number of elements do not match !".to_string())
                }
            },
        )
    }
}

impl Index<(usize, usize)> for Matrix {
    type Output = u32;

    #[inline]
    fn index(&self, index: (usize, usize)) -> &Self::Output {
        let (ridx, cidx) = index;
        unsafe { self.elems.get_unchecked(ridx * self.cols + cidx) }
    }
}

impl IndexMut<(usize, usize)> for Matrix {
    #[inline]
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        let (ridx, cidx) = index;
        unsafe { self.elems.get_unchecked_mut(ridx * self.cols + cidx) }
    }
}

impl Mul for Matrix {
    type Output = Option<Matrix>;

    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl<'a, 'b> Mul<&'b Matrix> for &'a Matrix {
    type Output = Option<Matrix>;

    fn mul(self, rhs: &'b Matrix) -> Self::Output {
        if branch_opt_util::unlikely(self.cols != rhs.rows) {
            return None;
        }

        let mut res = Matrix::new(self.rows, rhs.cols)?;

        (0..self.rows).for_each(|ridx| {
            (0..self.cols).for_each(|k| {
                (0..rhs.cols).for_each(|cidx| {
                    res[(ridx, cidx)] = res[(ridx, cidx)].wrapping_add(self[(ridx, k)].wrapping_mul(rhs[(k, cidx)]));
                });
            });
        });

        Some(res)
    }
}

impl Add for Matrix {
    type Output = Option<Matrix>;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl<'a, 'b> Add<&'b Matrix> for &'a Matrix {
    type Output = Option<Matrix>;

    fn add(self, rhs: &'b Matrix) -> Self::Output {
        if branch_opt_util::unlikely(!(self.rows == rhs.rows && self.cols == rhs.cols)) {
            return None;
        }

        let mut res = Matrix::new(self.rows, self.cols)?;

        (0..self.rows)
            .map(|ridx| (0..self.cols).map(move |cidx| (ridx, cidx)))
            .flatten()
            .for_each(|idx| {
                res[idx] = self[idx].wrapping_add(rhs[idx]);
            });

        Some(res)
    }
}

impl Sub for Matrix {
    type Output = Option<Matrix>;

    fn sub(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl<'a, 'b> Sub<&'b Matrix> for &'a Matrix {
    type Output = Option<Matrix>;

    fn sub(self, rhs: &'b Matrix) -> Self::Output {
        if branch_opt_util::unlikely(!(self.rows == rhs.rows && self.cols == rhs.cols)) {
            return None;
        }

        let mut res = Matrix::new(self.rows, self.cols)?;

        (0..self.rows)
            .map(|ridx| (0..self.cols).map(move |cidx| (ridx, cidx)))
            .flatten()
            .for_each(|idx| {
                res[idx] = self[idx].wrapping_sub(rhs[idx]);
            });

        Some(res)
    }
}

#[cfg(test)]
impl Neg for Matrix {
    type Output = Option<Matrix>;

    fn neg(self) -> Self::Output {
        -(&self)
    }
}

#[cfg(test)]
impl<'a> Neg for &'a Matrix {
    type Output = Option<Matrix>;

    fn neg(self) -> Self::Output {
        let mut res = Matrix::new(self.rows, self.cols)?;

        (0..self.rows)
            .map(|ridx| (0..self.cols).map(move |cidx| (ridx, cidx)))
            .flatten()
            .for_each(|idx| {
                res[idx] = self[idx].wrapping_neg();
            });

        Some(res)
    }
}

#[cfg(test)]
pub mod test {
    use crate::pir_internals::matrix::Matrix;
    use rand::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use std::collections::HashMap;

    pub fn generate_random_kv_database(num_kv_pairs: usize) -> HashMap<Vec<u8>, Vec<u8>> {
        const MIN_KEY_BYTE_LEN: usize = 16;
        const MAX_KEY_BYTE_LEN: usize = 32;
        const MIN_VALUE_BYTE_LEN: usize = 1;
        const MAX_VALUE_BYTE_LEN: usize = 512;

        let mut kv = HashMap::with_capacity(num_kv_pairs);
        let mut rng = ChaCha8Rng::from_entropy();

        for _ in 0..num_kv_pairs {
            let key_byte_len = rng.gen_range(MIN_KEY_BYTE_LEN..=MAX_KEY_BYTE_LEN);
            let value_byte_len = rng.gen_range(MIN_VALUE_BYTE_LEN..=MAX_VALUE_BYTE_LEN);

            let mut key = vec![0u8; key_byte_len];
            let mut value = vec![0u8; value_byte_len];

            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut value);

            kv.insert(key, value);
        }

        kv
    }

    #[test]
    fn encode_kv_database_using_3_wise_xor_filter_and_recover_values() {
        const MAX_FILTER_CONSTRUCTION_ATTEMPT_COUNT: usize = 100;
        const ARITY: u32 = 3;

        const MIN_NUM_KV_PAIRS: usize = 1_000;
        const MAX_NUM_KV_PAIRS: usize = 10_000;

        const MIN_MAT_ELEM_BIT_LEN: usize = 7;
        const MAX_MAT_ELEM_BIT_LEN: usize = 11;

        for num_kv_pairs in (MIN_NUM_KV_PAIRS..=MAX_NUM_KV_PAIRS).step_by(100) {
            for mat_elem_bit_len in MIN_MAT_ELEM_BIT_LEN..=MAX_MAT_ELEM_BIT_LEN {
                let kv_db = generate_random_kv_database(num_kv_pairs);
                let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

                let (db_mat, filter) = Matrix::from_kv_database::<ARITY>(kv_db_as_ref.clone(), mat_elem_bit_len, MAX_FILTER_CONSTRUCTION_ATTEMPT_COUNT)
                    .expect("Must be able to encode key-value database as matrix");

                for &key in kv_db_as_ref.keys() {
                    let expected_value = *kv_db_as_ref.get(key).expect("Value for queried key must be present");
                    let computed_value = db_mat
                        .recover_value_from_encoded_kv_database::<ARITY>(key, &filter)
                        .expect("Must be able to recover value from encoded key-value database matrix");

                    assert_eq!(
                        expected_value, computed_value,
                        "num_kv_pairs = {}, arity = {}, mat_elem_bit_len = {}",
                        num_kv_pairs, ARITY, mat_elem_bit_len
                    );
                }
            }
        }
    }

    #[test]
    fn encode_kv_database_using_4_wise_xor_filter_and_recover_values() {
        const MAX_FILTER_CONSTRUCTION_ATTEMPT_COUNT: usize = 100;
        const ARITY: u32 = 4;

        const MIN_NUM_KV_PAIRS: usize = 1_000;
        const MAX_NUM_KV_PAIRS: usize = 10_000;

        const MIN_MAT_ELEM_BIT_LEN: usize = 7;
        const MAX_MAT_ELEM_BIT_LEN: usize = 11;

        for num_kv_pairs in (MIN_NUM_KV_PAIRS..=MAX_NUM_KV_PAIRS).step_by(100) {
            for mat_elem_bit_len in MIN_MAT_ELEM_BIT_LEN..=MAX_MAT_ELEM_BIT_LEN {
                let kv_db = generate_random_kv_database(num_kv_pairs);
                let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

                let (db_mat, filter) = Matrix::from_kv_database::<ARITY>(kv_db_as_ref.clone(), mat_elem_bit_len, MAX_FILTER_CONSTRUCTION_ATTEMPT_COUNT)
                    .expect("Must be able to encode key-value database as matrix");

                for &key in kv_db_as_ref.keys() {
                    let expected_value = *kv_db_as_ref.get(key).expect("Value for queried key must be present");
                    let computed_value = db_mat
                        .recover_value_from_encoded_kv_database::<ARITY>(key, &filter)
                        .expect("Must be able to recover value from encoded key-value database matrix");

                    assert_eq!(
                        expected_value, computed_value,
                        "num_kv_pairs = {}, arity = {}, mat_elem_bit_len = {}",
                        num_kv_pairs, ARITY, mat_elem_bit_len
                    );
                }
            }
        }
    }

    #[test]
    fn matrix_multiplication_is_correct() {
        const NUM_ROWS_IN_MATRIX: usize = 1024;
        const NUM_COLS_IN_MATRIX: usize = NUM_ROWS_IN_MATRIX + 1;

        let mut rng = ChaCha8Rng::from_entropy();

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let matrix_a = Matrix::generate_from_seed(NUM_ROWS_IN_MATRIX, NUM_COLS_IN_MATRIX, &seed).expect("Matrix must be generated from seed");
        let matrix_i = Matrix::identity(NUM_COLS_IN_MATRIX).expect("Identity matrix must be created");
        let matrix_i_prime = Matrix::identity(NUM_ROWS_IN_MATRIX).expect("Identity matrix must be created");

        let matrix_ai = (&matrix_a * &matrix_i).expect("Matrix multiplication must pass");
        assert_eq!(matrix_a, matrix_ai);

        let matrix_ia = (&matrix_i_prime * &matrix_a).expect("Matrix multiplication must pass");
        assert_eq!(matrix_a, matrix_ia);
    }

    #[test]
    fn matrix_addition_is_correct() {
        const NUM_ROWS_IN_MATRIX: usize = 1024;
        const NUM_COLS_IN_MATRIX: usize = NUM_ROWS_IN_MATRIX + 1;

        let mut rng = ChaCha8Rng::from_entropy();

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let matrix_a = Matrix::generate_from_seed(NUM_ROWS_IN_MATRIX, NUM_COLS_IN_MATRIX, &seed).expect("Matrix must be generated from seed");
        let matrix_neg_a = (-&matrix_a).expect("Must be able to negate matrix");

        let matrix_a_plus_neg_a = (&matrix_a + &matrix_neg_a).expect("Matrix addition must pass");
        let matrix_zero = Matrix::new(NUM_ROWS_IN_MATRIX, NUM_COLS_IN_MATRIX).expect("Must be able to create zero matrix");

        assert_eq!(matrix_a_plus_neg_a, matrix_zero);
    }

    #[test]
    fn serialized_matrix_can_be_deserialized() {
        const NUM_ROWS_IN_MATRIX: usize = 1024;
        const NUM_COLS_IN_MATRIX: usize = NUM_ROWS_IN_MATRIX + 1;

        let mut rng = ChaCha8Rng::from_entropy();

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let matrix_a = Matrix::generate_from_seed(NUM_ROWS_IN_MATRIX, NUM_COLS_IN_MATRIX, &seed).expect("Matrix must be generated from seed");
        let matrix_a_bytes = matrix_a.to_bytes().unwrap();
        let matrix_b = Matrix::from_bytes(&matrix_a_bytes).unwrap();

        assert_eq!(matrix_a, matrix_b);
    }

    #[test]
    fn validate_bits_per_entry_for_3_wise_xor_filter() {
        const MAX_FILTER_CONSTRUCTION_ATTEMPT_COUNT: usize = 100;
        const ARITY: u32 = 3;
        const NUM_KV_PAIRS: usize = 1_000_000;
        const MAT_ELEM_BIT_LEN: usize = 10;
        const EXPECTED_BPE: f64 = (MAT_ELEM_BIT_LEN as f64) * 1.13; // From section 4 of ia.cr/2024/092

        let kv_db = generate_random_kv_database(NUM_KV_PAIRS);
        let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

        let (_, filter) = Matrix::from_kv_database::<ARITY>(kv_db_as_ref, MAT_ELEM_BIT_LEN, MAX_FILTER_CONSTRUCTION_ATTEMPT_COUNT).unwrap();

        let computed_bpe = filter.bits_per_entry();
        assert!(computed_bpe <= EXPECTED_BPE.ceil());
    }

    #[test]
    fn validate_bits_per_entry_for_4_wise_xor_filter() {
        const MAX_FILTER_CONSTRUCTION_ATTEMPT_COUNT: usize = 100;
        const ARITY: u32 = 4;
        const NUM_KV_PAIRS: usize = 1_000_000;
        const MAT_ELEM_BIT_LEN: usize = 10;
        const EXPECTED_BPE: f64 = (MAT_ELEM_BIT_LEN as f64) * 1.08; // From section 4 of ia.cr/2024/092

        let kv_db = generate_random_kv_database(NUM_KV_PAIRS);
        let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

        let (_, filter) = Matrix::from_kv_database::<ARITY>(kv_db_as_ref, MAT_ELEM_BIT_LEN, MAX_FILTER_CONSTRUCTION_ATTEMPT_COUNT).unwrap();

        let computed_bpe = filter.bits_per_entry();
        assert!(computed_bpe <= EXPECTED_BPE.ceil());
    }
}
