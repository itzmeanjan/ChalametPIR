use crate::pir_internals::{
    binary_fuse_filter, branch_opt_util,
    params::{HASHED_KEY_BYTE_LEN, SEED_BYTE_LEN},
    serialization,
};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;
use std::{
    collections::HashMap,
    ops::{Add, Index, IndexMut, Mul},
};
use turboshake::TurboShake128;

#[cfg(test)]
use std::ops::Neg;

use super::error::ChalametPIRError;

#[derive(Clone, Debug, PartialEq)]
pub struct Matrix {
    rows: u32,
    cols: u32,
    elems: Vec<u32>,
}

impl Matrix {
    /// Creates a new matrix with the given number of rows and columns, s.t. all elements are zero-initialized.
    ///
    /// # Arguments
    ///
    /// * `rows` - The number of rows in the matrix.
    /// * `cols` - The number of columns in the matrix.
    ///
    /// # Returns
    ///
    /// * `Result<Matrix, ChalametPIRError>` - A new matrix if the input is valid (rows and cols are positive).
    ///   Returns an error if either rows or cols is zero.
    pub fn new(rows: u32, cols: u32) -> Result<Matrix, ChalametPIRError> {
        if branch_opt_util::likely((rows > 0) && (cols > 0)) {
            Ok(Matrix {
                rows,
                cols,
                elems: vec![0; (rows * cols) as usize],
            })
        } else {
            Err(ChalametPIRError::InvalidMatrixDimension)
        }
    }

    /// Creates a new matrix with the given number of rows and columns, s.t. elements are initialized with the given values.
    ///
    /// # Arguments
    ///
    /// * `rows` - The number of rows in the matrix.
    /// * `cols` - The number of columns in the matrix.
    /// * `values` - The values to initialize the matrix with.
    ///
    /// # Returns
    ///
    /// * `Result<Matrix, ChalametPIRError>` - A new matrix if the input is valid (rows and cols are positive and the number of values matches the number of required elements).
    ///   Returns an error if either rows or cols is zero, or if the number of values does not match the number of required elements.
    pub fn from_values(rows: u32, cols: u32, values: Vec<u32>) -> Result<Matrix, ChalametPIRError> {
        if branch_opt_util::likely((rows > 0) && (cols > 0)) {
            if branch_opt_util::likely((rows * cols) as usize == values.len()) {
                Ok(Matrix { rows, cols, elems: values })
            } else {
                Err(ChalametPIRError::InvalidNumberOfElementsInMatrix)
            }
        } else {
            Err(ChalametPIRError::InvalidMatrixDimension)
        }
    }

    #[inline(always)]
    pub const fn num_rows(&self) -> u32 {
        self.rows
    }
    #[inline(always)]
    pub const fn num_cols(&self) -> u32 {
        self.cols
    }
    #[inline(always)]
    pub fn num_elems(&self) -> usize {
        self.elems.len()
    }
    #[inline(always)]
    pub fn num_bytes(&self) -> usize {
        std::mem::size_of_val(&self.rows) + std::mem::size_of_val(&self.cols) + std::mem::size_of::<u32>() * (self.rows * self.cols) as usize
    }

    pub fn row_wise_compress(self, mat_elem_bit_len: usize) -> Result<Matrix, ChalametPIRError> {
        if mat_elem_bit_len > u16::BITS as usize {
            return Err(ChalametPIRError::ImpossibleEncodedDBMatrixElementBitLength);
        }

        let mat_elem_mask = (1u32 << mat_elem_bit_len) - 1;

        let res_num_rows = self.rows;
        let res_num_cols = self.cols.div_ceil(2);

        let mut res = unsafe { Matrix::new(res_num_rows, res_num_cols).unwrap_unchecked() };

        (0..res_num_rows as usize)
            .flat_map(|ridx| (0..res_num_cols as usize).map(move |cidx| (ridx, cidx)))
            .for_each(|(ridx, cidx)| {
                let decompressed_elem_cidx = cidx * 2;

                let compressed_elem = if branch_opt_util::likely((decompressed_elem_cidx + 1) < self.cols as usize) {
                    ((self[(ridx, decompressed_elem_cidx + 1)] & mat_elem_mask) << u16::BITS) | (self[(ridx, decompressed_elem_cidx)] & mat_elem_mask)
                } else {
                    self[(ridx, decompressed_elem_cidx)] & mat_elem_mask
                };

                res[(ridx, cidx)] = compressed_elem;
            });

        Ok(res)
    }

    #[cfg(test)]
    pub fn row_wise_decompress(self, mat_elem_bit_len: usize, num_cols: u32) -> Result<Matrix, ChalametPIRError> {
        if mat_elem_bit_len > u16::BITS as usize {
            return Err(ChalametPIRError::ImpossibleEncodedDBMatrixElementBitLength);
        }

        let mat_elem_mask = (1u32 << mat_elem_bit_len) - 1;

        assert_eq!(num_cols.div_ceil(2), self.cols);

        let res_num_rows = self.rows;
        let res_num_cols = num_cols;

        let mut res = unsafe { Matrix::new(res_num_rows, res_num_cols).unwrap_unchecked() };

        (0..self.rows as usize)
            .flat_map(|src_ridx| (0..self.cols as usize).map(move |src_cidx| (src_ridx, src_cidx)))
            .for_each(|(src_ridx, src_cidx)| {
                let decompressed_elem_cidx = src_cidx * 2;

                res[(src_ridx, decompressed_elem_cidx)] = self[(src_ridx, src_cidx)] & mat_elem_mask;
                if branch_opt_util::likely((decompressed_elem_cidx + 1) < num_cols as usize) {
                    res[(src_ridx, decompressed_elem_cidx + 1)] = (self[(src_ridx, src_cidx)] >> u16::BITS) & mat_elem_mask;
                }
            });

        Ok(res)
    }

    /// Performs the multiplication of a row vector (1xN matrix) by a compressed representation of the transpose of a matrix (MxN).
    ///
    /// # Arguments
    ///
    /// * `rhs` - The compressed matrix to multiply with (MxN). Decompression is performed on the fly.
    ///
    /// # Returns
    ///
    /// * `Result<Matrix, ChalametPIRError>` - The resulting matrix (1xM) if the input is valid.
    ///   Returns an error if the input is invalid (self is not a row vector, or the dimensions are incompatible).
    pub fn row_vector_x_compressed_transposed_matrix(&self, rhs: &Matrix, decompressed_num_cols: u32) -> Result<Matrix, ChalametPIRError> {
        if branch_opt_util::unlikely(!(self.rows == 1 && self.cols == decompressed_num_cols)) {
            return Err(ChalametPIRError::IncompatibleDimensionForRowVectorTransposedMatrixMultiplication);
        }

        let res_num_rows = self.rows;
        let res_num_cols = rhs.rows;

        let mut res_elems = vec![0u32; (res_num_rows * res_num_cols) as usize];

        res_elems.par_iter_mut().enumerate().for_each(|(lin_idx, res_elem)| {
            let r_idx = 0;
            let c_idx = lin_idx;

            if self.cols & 1 == 0 {
                *res_elem = (0..rhs.cols as usize).fold(0u32, |acc, compressed_elem_cidx| {
                    let decompressed_elem_cidx = compressed_elem_cidx * 2;
                    let compressed_elem = rhs[(c_idx, compressed_elem_cidx)];

                    acc.wrapping_add(
                        self[(r_idx, decompressed_elem_cidx)]
                            .wrapping_mul(compressed_elem as u16 as u32)
                            .wrapping_add(self[(r_idx, decompressed_elem_cidx + 1)].wrapping_mul(compressed_elem >> u16::BITS)),
                    )
                });
            } else {
                *res_elem = (0..rhs.cols as usize).fold(0u32, |mut acc, compressed_elem_cidx| {
                    let decompressed_elem_cidx = compressed_elem_cidx * 2;
                    let compressed_elem = rhs[(c_idx, compressed_elem_cidx)];

                    acc = acc.wrapping_add(self[(r_idx, decompressed_elem_cidx)].wrapping_mul(compressed_elem as u16 as u32));

                    if branch_opt_util::likely(decompressed_elem_cidx + 1 < self.cols as usize) {
                        acc = acc.wrapping_add(self[(r_idx, decompressed_elem_cidx + 1)].wrapping_mul(compressed_elem >> u16::BITS));
                    }

                    acc
                });
            }
        });

        Matrix::from_values(res_num_rows, res_num_cols, res_elems)
    }

    /// Performs the multiplication of a row vector (1xN matrix) by the transpose of a matrix (MxN).
    ///
    /// # Arguments
    ///
    /// * `rhs` - The matrix to multiply with (MxN).
    ///
    /// # Returns
    ///
    /// * `Result<Matrix, ChalametPIRError>` - The resulting matrix (1xM) if the input is valid.
    ///   Returns an error if the input is invalid (self is not a row vector, or the dimensions are incompatible).
    pub fn row_vector_x_transposed_matrix(&self, rhs: &Matrix) -> Result<Matrix, ChalametPIRError> {
        if branch_opt_util::unlikely(!(self.rows == 1 && self.cols == rhs.cols)) {
            return Err(ChalametPIRError::IncompatibleDimensionForRowVectorTransposedMatrixMultiplication);
        }

        let res_num_rows = self.rows;
        let res_num_cols = rhs.rows;

        let mut res_elems = vec![0u32; (res_num_rows * res_num_cols) as usize];

        res_elems.par_iter_mut().enumerate().for_each(|(lin_idx, v)| {
            let r_idx = 0;
            let c_idx = lin_idx;

            *v = (0..self.cols as usize).fold(0u32, |acc, k| acc.wrapping_add(self[(r_idx, k)].wrapping_mul(rhs[(c_idx, k)])));
        });

        Matrix::from_values(res_num_rows, res_num_cols, res_elems)
    }

    /// Creates a new identity matrix of requested dimension.
    ///
    /// # Arguments
    ///
    /// * `rows` - The number of rows and columns in the identity matrix.
    ///
    /// # Returns
    ///
    /// * `Result<Matrix, ChalametPIRError>` - A new identity matrix if the input is valid (rows is positive).
    ///   Returns an error if rows is zero.
    #[cfg(test)]
    pub fn identity(rows: u32) -> Result<Matrix, ChalametPIRError> {
        if branch_opt_util::unlikely(rows == 0) {
            return Err(ChalametPIRError::InvalidMatrixDimension);
        }

        let mut mat = Matrix::new(rows, rows)?;

        (0..mat.rows as usize).for_each(|idx| {
            mat[(idx, idx)] = 1;
        });

        Ok(mat)
    }

    /// Transposes the matrix.
    ///
    /// # Returns
    ///
    /// * `Matrix` - The transposed matrix.
    pub fn transpose(&self) -> Matrix {
        let mut res = unsafe { Matrix::new(self.cols, self.rows).unwrap_unchecked() };

        (0..self.cols as usize)
            .flat_map(|ridx| (0..self.rows as usize).map(move |cidx| (ridx, cidx)))
            .for_each(|(ridx, cidx)| {
                res[(ridx, cidx)] = self[(cidx, ridx)];
            });

        res
    }

    /// Generates a matrix with the given dimensions from a SEED_BYTE_LEN -byte seed using TurboSHAKE128 xof.
    ///
    /// # Arguments
    ///
    /// * `rows` - The number of rows in the matrix.
    /// * `cols` - The number of columns in the matrix.
    /// * `seed` - The SEED_BYTE_LEN -byte seed to use for generation.
    ///
    /// # Returns
    ///
    /// * `Result<Matrix, ChalametPIRError>` - A new matrix if the input is valid (rows and cols are positive).
    ///   Returns an error if either rows or cols is zero.
    pub fn generate_from_seed(rows: u32, cols: u32, seed: &[u8; SEED_BYTE_LEN]) -> Result<Matrix, ChalametPIRError> {
        let mut hasher = TurboShake128::default();
        hasher.absorb(seed);
        hasher.finalize::<{ TurboShake128::DEFAULT_DOMAIN_SEPARATOR }>();

        let mut elems = vec![0u32; (rows * cols) as usize];
        let elems_byte_len = elems.len() * std::mem::size_of::<u32>();

        unsafe {
            let ptr_elems = elems.as_mut_ptr();
            let ptr_elem_bytes: *mut u8 = ptr_elems.cast();
            let elem_bytes = core::slice::from_raw_parts_mut(ptr_elem_bytes, elems_byte_len);

            hasher.squeeze(elem_bytes);
        }

        Matrix::from_values(rows, cols, elems)
    }

    /// Generates a row/ column vector with the given dimensions, where each element is sampled from a uniform ternary distribution {0, 1, -1}.
    /// Note, -1 is represented as u32::MAX.
    ///
    /// # Arguments
    ///
    /// * `rows` - The number of rows in the matrix.
    /// * `cols` - The number of columns in the matrix.
    ///
    /// # Returns
    ///
    /// * `Result<Matrix, ChalametPIRError>` - A new row/ column vector if the input is valid (rows or cols is 1).
    ///   Returns an error if neither rows nor cols is 1.
    pub fn sample_from_uniform_ternary_dist(rows: u32, cols: u32) -> Result<Matrix, ChalametPIRError> {
        if branch_opt_util::unlikely(!(rows == 1 || cols == 1)) {
            return Err(ChalametPIRError::InvalidDimensionForVector);
        }

        const TERNARY_INTERVAL_SIZE: u32 = (u32::MAX - 2) / 3;
        const TERNARY_REJECTION_SAMPLING_MAX: u32 = TERNARY_INTERVAL_SIZE * 3;

        let mut rng = ChaCha8Rng::from_os_rng();
        let mut vec = Matrix::new(rows, cols)?;

        let num_elems = vec.num_elems();
        let mut elem_idx = 0;

        while branch_opt_util::likely(elem_idx < num_elems) {
            let mut val = rng.random::<u32>();

            while branch_opt_util::unlikely(val > TERNARY_REJECTION_SAMPLING_MAX) {
                val = rng.random::<u32>();
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

        Ok(vec)
    }

    /// Encodes a key-value database as a matrix using column-wise Binary Fuse Filters. Each filter column represents bits of a (hashed-key, value) pair; each row represents a complete (256-bit hashed-key, value) pair.
    ///
    /// # Arguments
    ///
    /// * `db` - The key-value database to encode.  Keys and values need not be of uniform length.
    /// * `mat_elem_bit_len` - The number of bits per element in the resulting matrix.
    /// * `max_attempt_count` - The maximum number of attempts to construct the filter.
    ///
    /// # Returns
    ///
    /// * `Result<(Matrix, BinaryFuseFilter), ChalametPIRError>` - A tuple containing the resulting matrix and the Binary Fuse Filter.
    ///   Returns an error if filter construction fails.
    pub fn from_kv_database<const ARITY: u32>(
        db: HashMap<&[u8], &[u8]>,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Result<(Matrix, binary_fuse_filter::BinaryFuseFilter), ChalametPIRError> {
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

    /// Recovers the value associated with the given key from the encoded key-value database matrix.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to search for.
    /// * `filter` - The Binary Fuse Filter used to encode the key-value database.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, ChalametPIRError>` - The value associated with the key if found.
    ///   Returns an error if the key is not found or if an error occurs during value recovery.
    #[cfg(test)]
    fn recover_value_from_encoded_kv_database<const ARITY: u32>(&self, key: &[u8], filter: &binary_fuse_filter::BinaryFuseFilter) -> Result<Vec<u8>, ChalametPIRError> {
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

    /// Encodes a key-value database as a matrix using 3-wise XOR Binary Fuse Filters. Each filter column represents bits of a (hashed-key, value) pair; each row represents a complete (256-bit hashed-key, value) pair.
    ///
    /// # Arguments
    ///
    /// * `db` - The key-value database to encode. Keys and values need not be of uniform length.
    /// * `mat_elem_bit_len` - The number of bits per element in the resulting matrix.
    /// * `max_attempt_count` - The maximum number of attempts to construct the filter.
    ///
    /// # Returns
    ///
    /// * `Result<(Matrix, BinaryFuseFilter), ChalametPIRError>` - A tuple containing the resulting matrix and the Binary Fuse Filter.
    ///   Returns an error if filter construction fails.
    fn from_kv_database_with_3_wise_xor_filter(
        db: HashMap<&[u8], &[u8]>,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Result<(Matrix, binary_fuse_filter::BinaryFuseFilter), ChalametPIRError> {
        match binary_fuse_filter::BinaryFuseFilter::construct_3_wise_xor_filter(&db, mat_elem_bit_len, max_attempt_count) {
            Ok((filter, reverse_order, reverse_h, hash_to_key)) => {
                const HASHED_KEY_BIT_LEN: usize = 256;

                let max_value_byte_len = unsafe { db.values().map(|v| v.len()).max().unwrap_unchecked() };
                let max_value_bit_len = max_value_byte_len * 8;

                let rows = filter.num_fingerprints as u32;
                let cols = (HASHED_KEY_BIT_LEN + max_value_bit_len + 8).div_ceil(mat_elem_bit_len) as u32;

                let mut mat = Matrix::new(rows, cols)?;
                let mat_elem_mask = (1u32 << mat_elem_bit_len) - 1;

                let mut h012 = [0u32; 5];

                for i in (0..filter.filter_size).rev() {
                    let hash = reverse_order[i];
                    let key = unsafe { *hash_to_key.get(&hash).unwrap_unchecked() };
                    let value = unsafe { *db.get(key).unwrap_unchecked() };

                    let (h0, h1, h2) = binary_fuse_filter::hash_batch_for_3_wise_xor_filter(hash, filter.segment_length, filter.segment_count_length);

                    let found = reverse_h[i] as usize;
                    h012[0] = h0;
                    h012[1] = h1;
                    h012[2] = h2;
                    h012[3] = h012[0];
                    h012[4] = h012[1];

                    let row = serialization::encode_kv_as_row(key, value, mat_elem_bit_len, cols);

                    let mat_row_idx0 = h012[found] as usize;
                    let mat_row_idx1 = h012[found + 1] as usize;
                    let mat_row_idx2 = h012[found + 2] as usize;

                    let elems = (0..cols as usize)
                        .map(|elem_idx| {
                            let f1 = mat.elems[mat_row_idx1 * cols as usize + elem_idx];
                            (elem_idx, row[elem_idx].wrapping_sub(f1))
                        })
                        .map(|(elem_idx, elem)| {
                            let f2 = mat.elems[mat_row_idx2 * cols as usize + elem_idx];
                            (elem_idx, elem.wrapping_sub(f2) & mat_elem_mask)
                        })
                        .map(|(elem_idx, elem)| {
                            let mask = (binary_fuse_filter::mix(hash, elem_idx as u64) as u32) & mat_elem_mask;
                            elem.wrapping_sub(mask) & mat_elem_mask
                        })
                        .collect::<Vec<u32>>();

                    let fingerprints_begin_at = mat_row_idx0 * cols as usize;
                    let fingerprints_end_at = fingerprints_begin_at + cols as usize;

                    mat.elems[fingerprints_begin_at..fingerprints_end_at].copy_from_slice(&elems);
                }

                Ok((mat, filter))
            }
            Err(e) => {
                branch_opt_util::cold();
                Err(e)
            }
        }
    }

    /// Recovers the value associated with the given key from the encoded key-value database matrix using a 3-wise XOR filter.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to search for.
    /// * `filter` - The 3-wise XOR Binary Fuse Filter used to encode the key-value database.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, ChalametPIRError>` - The value associated with the key if found.
    ///   Returns an error if the key is not found or if an error occurs during value recovery.
    #[cfg(test)]
    fn recover_value_from_3_wise_xor_filter(&self, key: &[u8], filter: &binary_fuse_filter::BinaryFuseFilter) -> Result<Vec<u8>, ChalametPIRError> {
        let mat_elem_mask = (1u32 << filter.mat_elem_bit_len) - 1;

        let hashed_key = binary_fuse_filter::hash_of_key(key);
        let hash = binary_fuse_filter::mix256(&hashed_key, &filter.seed);

        let (h0, h1, h2) = binary_fuse_filter::hash_batch_for_3_wise_xor_filter(hash, filter.segment_length, filter.segment_count_length);

        let recovered_row = (0..self.cols as usize)
            .map(|elem_idx| (elem_idx, self.elems[h0 as usize * self.cols as usize + elem_idx]))
            .map(|(elem_idx, elem)| (elem_idx, elem.wrapping_add(self.elems[h1 as usize * self.cols as usize + elem_idx])))
            .map(|(elem_idx, elem)| (elem_idx, elem.wrapping_add(self.elems[h2 as usize * self.cols as usize + elem_idx])))
            .map(|(elem_idx, elem)| elem.wrapping_add((binary_fuse_filter::mix(hash, elem_idx as u64) as u32) & mat_elem_mask) & mat_elem_mask)
            .collect::<Vec<u32>>();

        match serialization::decode_kv_from_row(&recovered_row, filter.mat_elem_bit_len) {
            Ok(mut decoded_kv) => {
                let mut hashed_key_as_bytes = [0u8; HASHED_KEY_BYTE_LEN];

                hashed_key_as_bytes[..8].copy_from_slice(&hashed_key[0].to_le_bytes());
                hashed_key_as_bytes[8..16].copy_from_slice(&hashed_key[1].to_le_bytes());
                hashed_key_as_bytes[16..24].copy_from_slice(&hashed_key[2].to_le_bytes());
                hashed_key_as_bytes[24..].copy_from_slice(&hashed_key[3].to_le_bytes());

                if branch_opt_util::likely((0..hashed_key_as_bytes.len()).fold(0u8, |acc, idx| acc ^ (decoded_kv[idx] ^ hashed_key_as_bytes[idx])) == 0) {
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
        }
    }

    /// Encodes a key-value database as a matrix using 4-wise XOR Binary Fuse Filters. Each filter column represents bits of a (hashed-key, value) pair; each row represents a complete (256-bit hashed-key, value) pair.
    ///
    /// # Arguments
    ///
    /// * `db` - The key-value database to encode. Keys and values need not be of uniform length.
    /// * `mat_elem_bit_len` - The number of bits per element in the resulting matrix.
    /// * `max_attempt_count` - The maximum number of attempts to construct the filter.
    ///
    /// # Returns
    ///
    /// * `Result<(Matrix, BinaryFuseFilter), ChalametPIRError>` - A tuple containing the resulting matrix and the Binary Fuse Filter.
    ///   Returns an error if filter construction fails.
    fn from_kv_database_with_4_wise_xor_filter(
        db: HashMap<&[u8], &[u8]>,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Result<(Matrix, binary_fuse_filter::BinaryFuseFilter), ChalametPIRError> {
        match binary_fuse_filter::BinaryFuseFilter::construct_4_wise_xor_filter(&db, mat_elem_bit_len, max_attempt_count) {
            Ok((filter, reverse_order, reverse_h, hash_to_key)) => {
                const HASHED_KEY_BIT_LEN: usize = HASHED_KEY_BYTE_LEN * 8;

                let max_value_byte_len = unsafe { db.values().map(|v| v.len()).max().unwrap_unchecked() };
                let max_value_bit_len = max_value_byte_len * 8;

                let rows = filter.num_fingerprints as u32;
                let cols = (HASHED_KEY_BIT_LEN + max_value_bit_len + 8).div_ceil(mat_elem_bit_len) as u32;

                let mut mat = Matrix::new(rows, cols)?;
                let mat_elem_mask = (1u32 << mat_elem_bit_len) - 1;

                let mut h0123 = [0u32; 7];

                for i in (0..filter.filter_size).rev() {
                    let hash = reverse_order[i];
                    let key = unsafe { *hash_to_key.get(&hash).unwrap_unchecked() };
                    let value = unsafe { *db.get(key).unwrap_unchecked() };

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

                    let mat_row_idx0 = h0123[found] as usize;
                    let mat_row_idx1 = h0123[found + 1] as usize;
                    let mat_row_idx2 = h0123[found + 2] as usize;
                    let mat_row_idx3 = h0123[found + 3] as usize;

                    let elems = (0..cols as usize)
                        .map(|elem_idx| {
                            let f1 = mat.elems[mat_row_idx1 * cols as usize + elem_idx];
                            (elem_idx, row[elem_idx].wrapping_sub(f1))
                        })
                        .map(|(elem_idx, elem)| {
                            let f2 = mat.elems[mat_row_idx2 * cols as usize + elem_idx];
                            (elem_idx, elem.wrapping_sub(f2) & mat_elem_mask)
                        })
                        .map(|(elem_idx, elem)| {
                            let f2 = mat.elems[mat_row_idx3 * cols as usize + elem_idx];
                            (elem_idx, elem.wrapping_sub(f2) & mat_elem_mask)
                        })
                        .map(|(elem_idx, elem)| {
                            let mask = (binary_fuse_filter::mix(hash, elem_idx as u64) as u32) & mat_elem_mask;
                            elem.wrapping_sub(mask) & mat_elem_mask
                        })
                        .collect::<Vec<u32>>();

                    let fingerprints_begin_at = mat_row_idx0 * cols as usize;
                    let fingerprints_end_at = fingerprints_begin_at + cols as usize;

                    mat.elems[fingerprints_begin_at..fingerprints_end_at].copy_from_slice(&elems);
                }

                Ok((mat, filter))
            }
            Err(e) => {
                branch_opt_util::cold();
                Err(e)
            }
        }
    }

    /// Recovers the value associated with the given key from the encoded key-value database matrix using a 4-wise XOR filter.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to search for.
    /// * `filter` - The 4-wise XOR Binary Fuse Filter used to encode the key-value database.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, ChalametPIRError>` - The value associated with the key if found.
    ///     Returns an error if the key is not found or if an error occurs during value recovery.
    #[cfg(test)]
    fn recover_value_from_4_wise_xor_filter(&self, key: &[u8], filter: &binary_fuse_filter::BinaryFuseFilter) -> Result<Vec<u8>, ChalametPIRError> {
        let mat_elem_mask = (1u32 << filter.mat_elem_bit_len) - 1;

        let hashed_key = binary_fuse_filter::hash_of_key(key);
        let hash = binary_fuse_filter::mix256(&hashed_key, &filter.seed);

        let (h0, h1, h2, h3) = binary_fuse_filter::hash_batch_for_4_wise_xor_filter(hash, filter.segment_length, filter.segment_count_length);

        let recovered_row = (0..self.cols as usize)
            .map(|elem_idx| (elem_idx, self.elems[h0 as usize * self.cols as usize + elem_idx]))
            .map(|(elem_idx, elem)| (elem_idx, elem.wrapping_add(self.elems[h1 as usize * self.cols as usize + elem_idx])))
            .map(|(elem_idx, elem)| (elem_idx, elem.wrapping_add(self.elems[h2 as usize * self.cols as usize + elem_idx])))
            .map(|(elem_idx, elem)| (elem_idx, elem.wrapping_add(self.elems[h3 as usize * self.cols as usize + elem_idx])))
            .map(|(elem_idx, elem)| elem.wrapping_add((binary_fuse_filter::mix(hash, elem_idx as u64) as u32) & mat_elem_mask) & mat_elem_mask)
            .collect::<Vec<u32>>();

        match serialization::decode_kv_from_row(&recovered_row, filter.mat_elem_bit_len) {
            Ok(mut decoded_kv) => {
                let mut hashed_key_as_bytes = [0u8; HASHED_KEY_BYTE_LEN];

                hashed_key_as_bytes[..8].copy_from_slice(&hashed_key[0].to_le_bytes());
                hashed_key_as_bytes[8..16].copy_from_slice(&hashed_key[1].to_le_bytes());
                hashed_key_as_bytes[16..24].copy_from_slice(&hashed_key[2].to_le_bytes());
                hashed_key_as_bytes[24..].copy_from_slice(&hashed_key[3].to_le_bytes());

                if branch_opt_util::likely((0..hashed_key_as_bytes.len()).fold(0u8, |acc, idx| acc ^ (decoded_kv[idx] ^ hashed_key_as_bytes[idx])) == 0) {
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
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let encoded_elems_byte_len = std::mem::size_of::<u32>() * (self.rows * self.cols) as usize;

        let offset0 = 0;
        let offset1 = offset0 + std::mem::size_of_val(&self.rows);
        let offset2 = offset1 + std::mem::size_of_val(&self.cols);
        let total_byte_len = offset2 + encoded_elems_byte_len;

        let elems_as_bytes = unsafe {
            let ptr_elems = self.elems.as_ptr();
            let ptr_elem_bytes: *const u8 = ptr_elems.cast();

            core::slice::from_raw_parts(ptr_elem_bytes, encoded_elems_byte_len)
        };

        let mut bytes = vec![0u8; total_byte_len];

        unsafe {
            bytes.get_unchecked_mut(offset0..offset1).copy_from_slice(&self.rows.to_le_bytes());
            bytes.get_unchecked_mut(offset1..offset2).copy_from_slice(&self.cols.to_le_bytes());
            bytes.get_unchecked_mut(offset2..).copy_from_slice(elems_as_bytes);
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Matrix, ChalametPIRError> {
        const OFFSET0: usize = 0;
        const OFFSET1: usize = OFFSET0 + std::mem::size_of::<u32>();
        const OFFSET2: usize = OFFSET1 + std::mem::size_of::<u32>();

        if branch_opt_util::unlikely(bytes.len() <= OFFSET2) {
            return Err(ChalametPIRError::FailedToDeserializeMatrixFromBytes);
        }

        let (rows, cols) = unsafe {
            (
                u32::from_le_bytes(bytes.get_unchecked(OFFSET0..OFFSET1).try_into().unwrap()),
                u32::from_le_bytes(bytes.get_unchecked(OFFSET1..OFFSET2).try_into().unwrap()),
            )
        };
        let num_elems = (rows * cols) as usize;

        if branch_opt_util::unlikely(num_elems == 0) {
            return Err(ChalametPIRError::FailedToDeserializeMatrixFromBytes);
        }

        let encoded_elems_byte_len = std::mem::size_of::<u32>() * num_elems;
        let remaining_num_bytes = bytes.len() - OFFSET2;

        if branch_opt_util::unlikely(encoded_elems_byte_len != remaining_num_bytes) {
            return Err(ChalametPIRError::FailedToDeserializeMatrixFromBytes);
        }

        let elems = unsafe {
            let ptr_elem_bytes = bytes[OFFSET2..].as_ptr();
            let ptr_elems: *const u32 = ptr_elem_bytes.cast();

            core::slice::from_raw_parts(ptr_elems, num_elems)
        }
        .to_vec();

        Ok(Matrix { rows, cols, elems })
    }
}

impl Index<(usize, usize)> for Matrix {
    type Output = u32;

    #[inline(always)]
    fn index(&self, index: (usize, usize)) -> &Self::Output {
        let (ridx, cidx) = index;
        unsafe { self.elems.get_unchecked(ridx * self.cols as usize + cidx) }
    }
}

impl IndexMut<(usize, usize)> for Matrix {
    #[inline(always)]
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        let (ridx, cidx) = index;
        unsafe { self.elems.get_unchecked_mut(ridx * self.cols as usize + cidx) }
    }
}

impl Mul for Matrix {
    type Output = Result<Matrix, ChalametPIRError>;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl<'b> Mul<&'b Matrix> for &Matrix {
    type Output = Result<Matrix, ChalametPIRError>;

    fn mul(self, rhs: &'b Matrix) -> Self::Output {
        if branch_opt_util::unlikely(self.cols != rhs.rows) {
            return Err(ChalametPIRError::IncompatibleDimensionForMatrixMultiplication);
        }

        let mut res_elems = vec![0u32; (self.rows * rhs.cols) as usize];

        res_elems.par_iter_mut().enumerate().for_each(|(lin_idx, v)| {
            let r_idx = lin_idx / rhs.cols as usize;
            let c_idx = lin_idx - r_idx * rhs.cols as usize;

            *v = (0..self.cols as usize).fold(0u32, |acc, k| acc.wrapping_add(self[(r_idx, k)].wrapping_mul(rhs[(k, c_idx)])));
        });

        Matrix::from_values(self.rows, rhs.cols, res_elems)
    }
}

impl Add for Matrix {
    type Output = Result<Matrix, ChalametPIRError>;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl<'b> Add<&'b Matrix> for &Matrix {
    type Output = Result<Matrix, ChalametPIRError>;

    fn add(self, rhs: &'b Matrix) -> Self::Output {
        if branch_opt_util::unlikely(!(self.rows == rhs.rows && self.cols == rhs.cols)) {
            return Err(ChalametPIRError::IncompatibleDimensionForMatrixAddition);
        }

        let mut res_elems = vec![0u32; (self.rows * rhs.cols) as usize];

        res_elems.par_iter_mut().enumerate().for_each(|(lin_idx, v)| {
            *v = unsafe { self.elems.get_unchecked(lin_idx).wrapping_add(*rhs.elems.get_unchecked(lin_idx)) };
        });

        Matrix::from_values(self.rows, rhs.cols, res_elems)
    }
}

#[cfg(test)]
impl Neg for Matrix {
    type Output = Result<Matrix, ChalametPIRError>;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        -(&self)
    }
}

#[cfg(test)]
impl Neg for &Matrix {
    type Output = Result<Matrix, ChalametPIRError>;

    fn neg(self) -> Self::Output {
        let mut res = Matrix::new(self.rows, self.cols)?;

        (0..self.num_elems()).for_each(|idx| {
            res.elems[idx] = self.elems[idx].wrapping_neg();
        });

        Ok(res)
    }
}

#[cfg(test)]
pub mod test {
    use crate::{
        SEED_BYTE_LEN,
        pir_internals::{binary_fuse_filter::BinaryFuseFilter, error::ChalametPIRError, matrix::Matrix, params::SERVER_SETUP_MAX_ATTEMPT_COUNT},
    };
    use rand::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use std::collections::HashMap;
    use test_case::test_case;

    /// Generates a random key-value database with the requested number of key-value pairs.
    ///
    /// # Arguments
    ///
    /// * `num_kv_pairs` - The number of key-value pairs to generate.
    ///
    /// # Returns
    ///
    /// * `HashMap<Vec<u8>, Vec<u8>>` - A HashMap containing the generated key-value pairs.
    ///   The keys and values are randomly generated byte arrays with lengths between fixed minimum and maximum values.
    pub fn generate_random_kv_database(num_kv_pairs: usize) -> HashMap<Vec<u8>, Vec<u8>> {
        const MIN_KEY_BYTE_LEN: usize = 16;
        const MAX_KEY_BYTE_LEN: usize = 32;
        const MIN_VALUE_BYTE_LEN: usize = 1;
        const MAX_VALUE_BYTE_LEN: usize = 512;

        let mut kv = HashMap::with_capacity(num_kv_pairs);
        let mut rng = ChaCha8Rng::from_os_rng();

        for _ in 0..num_kv_pairs {
            let key_byte_len = rng.random_range(MIN_KEY_BYTE_LEN..=MAX_KEY_BYTE_LEN);
            let value_byte_len = rng.random_range(MIN_VALUE_BYTE_LEN..=MAX_VALUE_BYTE_LEN);

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
        const ARITY: u32 = 3;

        const MIN_NUM_KV_PAIRS: usize = 1_000;
        const MAX_NUM_KV_PAIRS: usize = 10_000;

        const MIN_MAT_ELEM_BIT_LEN: usize = 7;
        const MAX_MAT_ELEM_BIT_LEN: usize = 11;

        for num_kv_pairs in (MIN_NUM_KV_PAIRS..=MAX_NUM_KV_PAIRS).step_by(100) {
            for mat_elem_bit_len in MIN_MAT_ELEM_BIT_LEN..=MAX_MAT_ELEM_BIT_LEN {
                let kv_db = generate_random_kv_database(num_kv_pairs);
                let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

                let (db_mat, filter) = Matrix::from_kv_database::<ARITY>(kv_db_as_ref.clone(), mat_elem_bit_len, SERVER_SETUP_MAX_ATTEMPT_COUNT)
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
        const ARITY: u32 = 4;

        const MIN_NUM_KV_PAIRS: usize = 1_000;
        const MAX_NUM_KV_PAIRS: usize = 10_000;

        const MIN_MAT_ELEM_BIT_LEN: usize = 7;
        const MAX_MAT_ELEM_BIT_LEN: usize = 11;

        for num_kv_pairs in (MIN_NUM_KV_PAIRS..=MAX_NUM_KV_PAIRS).step_by(100) {
            for mat_elem_bit_len in MIN_MAT_ELEM_BIT_LEN..=MAX_MAT_ELEM_BIT_LEN {
                let kv_db = generate_random_kv_database(num_kv_pairs);
                let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

                let (db_mat, filter) = Matrix::from_kv_database::<ARITY>(kv_db_as_ref.clone(), mat_elem_bit_len, SERVER_SETUP_MAX_ATTEMPT_COUNT)
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

    #[test_case(1024, 1024 => matches Ok(_);  "Non-zero number of rows and columns are valid")]
    #[test_case(0, 1024 => matches Err(ChalametPIRError::InvalidMatrixDimension);  "Number of rows must be greater than zero")]
    #[test_case(1024, 0 => matches Err(ChalametPIRError::InvalidMatrixDimension);  "Number of columns must be greater than zero")]
    #[test_case(0, 0 => matches Err(ChalametPIRError::InvalidMatrixDimension);  "Both number of rows and columns must be greater than zero")]
    fn new_empty_matrix_constructor_api(num_rows: u32, num_cols: u32) -> Result<Matrix, ChalametPIRError> {
        Matrix::new(num_rows, num_cols)
    }

    #[test_case(1024, 1024, vec![0u32; 1024 * 1024] => matches Ok(_);  "Non-zero number of rows and columns are valid")]
    #[test_case(0, 1024, vec![] => matches Err(ChalametPIRError::InvalidMatrixDimension);  "Number of rows must be greater than zero")]
    #[test_case(1024, 0, vec![] => matches Err(ChalametPIRError::InvalidMatrixDimension);  "Number of columns must be greater than zero")]
    #[test_case(0, 0, vec![] => matches Err(ChalametPIRError::InvalidMatrixDimension);  "Both number of rows and columns must be greater than zero")]
    #[test_case(1024, 1024, vec![0u32; 1024 * 1024 -1] => matches Err(ChalametPIRError::InvalidNumberOfElementsInMatrix);  "Number of elements must be equal to number of rows times number of columns")]
    fn from_values_matrix_constructor_api(num_rows: u32, num_cols: u32, elems: Vec<u32>) -> Result<Matrix, ChalametPIRError> {
        Matrix::from_values(num_rows, num_cols, elems)
    }

    #[test_case((1024,1),(1,1024) => matches Ok(_); "Matrix multiplication should work for valid dimensions")]
    #[test_case((1024,1),(1024, 1) => matches Err(ChalametPIRError::IncompatibleDimensionForMatrixMultiplication); "Matrix multiplication should not work for incompatible dimensions")]
    fn matrix_multiplication_failures(lhs_mat_dim: (u32, u32), rhs_mat_dim: (u32, u32)) -> Result<Matrix, ChalametPIRError> {
        let (lhs_mat_rows, lhs_mat_cols) = lhs_mat_dim;
        let lhs_mat = Matrix::new(lhs_mat_rows, lhs_mat_cols)?;

        let (rhs_mat_rows, rhs_mat_cols) = rhs_mat_dim;
        let rhs_mat = Matrix::new(rhs_mat_rows, rhs_mat_cols)?;

        lhs_mat * rhs_mat
    }

    #[test_case((1024,1),(1024, 1) => matches Ok(_); "Matrix addition should work for valid dimensions")]
    #[test_case((1024,1),(1, 1024) => matches Err(ChalametPIRError::IncompatibleDimensionForMatrixAddition); "Matrix addition should not work for incompatible dimensions")]
    fn matrix_addition_failures(lhs_mat_dim: (u32, u32), rhs_mat_dim: (u32, u32)) -> Result<Matrix, ChalametPIRError> {
        let (lhs_mat_rows, lhs_mat_cols) = lhs_mat_dim;
        let lhs_mat = Matrix::new(lhs_mat_rows, lhs_mat_cols)?;

        let (rhs_mat_rows, rhs_mat_cols) = rhs_mat_dim;
        let rhs_mat = Matrix::new(rhs_mat_rows, rhs_mat_cols)?;

        lhs_mat + rhs_mat
    }

    #[test]
    fn matrix_multiplication_is_correct() {
        const NUM_ATTEMPT_MATRIX_MULTIPLICATIONS: usize = 100;
        const MIN_MATRIX_DIM: u32 = 1;
        const MAX_MATRIX_DIM: u32 = 1024;

        let mut rng = ChaCha8Rng::from_os_rng();

        let mut seed = [0u8; SEED_BYTE_LEN];
        rng.fill_bytes(&mut seed);

        let mut current_attempt_count = 0;
        while current_attempt_count < NUM_ATTEMPT_MATRIX_MULTIPLICATIONS {
            let num_rows = rng.random_range(MIN_MATRIX_DIM..=MAX_MATRIX_DIM);
            let num_cols = rng.random_range(MIN_MATRIX_DIM..=MAX_MATRIX_DIM);

            let matrix_a = Matrix::generate_from_seed(num_rows, num_cols, &seed).expect("Matrix must be generated from seed");
            let matrix_i = Matrix::identity(num_cols).expect("Identity matrix must be created");
            let matrix_i_prime = Matrix::identity(num_rows).expect("Identity matrix must be created");

            let matrix_ai = (&matrix_a * &matrix_i).expect("Matrix multiplication must pass");
            assert_eq!(matrix_a, matrix_ai);

            let matrix_ia = (&matrix_i_prime * &matrix_a).expect("Matrix multiplication must pass");
            assert_eq!(matrix_a, matrix_ia);

            current_attempt_count += 1;
        }
    }

    #[test]
    fn row_vector_transposed_matrix_multiplication_works() {
        const NUM_ATTEMPT_VECTOR_MATRIX_MULTIPLICATIONS: usize = 100;
        const MIN_ROW_VECTOR_DIM: u32 = 1;
        const MAX_ROW_VECTOR_DIM: u32 = 1024;

        let mut rng = ChaCha8Rng::from_os_rng();

        let mut seed = [0u8; SEED_BYTE_LEN];
        rng.fill_bytes(&mut seed);

        let mut current_attempt_count = 0;
        while current_attempt_count < NUM_ATTEMPT_VECTOR_MATRIX_MULTIPLICATIONS {
            let vec_num_rows = 1;
            let vec_num_cols = rng.random_range(MIN_ROW_VECTOR_DIM..=MAX_ROW_VECTOR_DIM);
            let mat_num_rows = vec_num_cols;
            let mat_num_cols = rng.random_range(MIN_ROW_VECTOR_DIM..=MAX_ROW_VECTOR_DIM);
            let mat_num_elems = (mat_num_rows * mat_num_cols) as usize;

            let row_vector = Matrix::generate_from_seed(vec_num_rows, vec_num_cols, &seed).expect("Row vector must be generated from seed");
            let all_ones = Matrix::from_values(mat_num_rows, mat_num_cols, vec![1; mat_num_elems]).expect("Matrix of ones must be created");
            let transposed_all_ones = all_ones.transpose();

            let res_row_vector = row_vector
                .row_vector_x_transposed_matrix(&transposed_all_ones)
                .expect("Row vector matrix multiplication must pass");

            let expected_res_row_vector = {
                let sum_of_elems_in_row_vector = row_vector.elems.iter().fold(0u32, |acc, &cur| acc.wrapping_add(cur));
                let row_vec_elems = vec![sum_of_elems_in_row_vector; mat_num_cols as usize];

                Matrix::from_values(vec_num_rows, mat_num_cols, row_vec_elems).expect("Expected row vector must be created")
            };
            assert_eq!(expected_res_row_vector, res_row_vector);

            current_attempt_count += 1;
        }
    }

    #[test]
    fn matrix_addition_is_correct() {
        const NUM_ATTEMPT_MATRIX_ADDITIONS: usize = 100;
        const MIN_MATRIX_DIM: u32 = 1;
        const MAX_MATRIX_DIM: u32 = 1024;

        let mut rng = ChaCha8Rng::from_os_rng();

        let mut seed = [0u8; SEED_BYTE_LEN];
        rng.fill_bytes(&mut seed);

        let mut current_attempt_count = 0;
        while current_attempt_count < NUM_ATTEMPT_MATRIX_ADDITIONS {
            let num_rows = rng.random_range(MIN_MATRIX_DIM..=MAX_MATRIX_DIM);
            let num_cols = rng.random_range(MIN_MATRIX_DIM..=MAX_MATRIX_DIM);

            let matrix_a = Matrix::generate_from_seed(num_rows, num_cols, &seed).expect("Matrix must be generated from seed");
            let matrix_neg_a = (-&matrix_a).expect("Must be able to negate matrix");

            let matrix_a_plus_neg_a = (&matrix_a + &matrix_neg_a).expect("Matrix addition must pass");
            let matrix_zero = Matrix::new(num_rows, num_cols).expect("Must be able to create zero matrix");

            assert_eq!(matrix_a_plus_neg_a, matrix_zero);

            current_attempt_count += 1;
        }
    }

    #[test_case(1, 1024  => matches Ok(_); "Can sample row vector")]
    #[test_case(1024, 1  => matches Ok(_); "Can sample column vector")]
    #[test_case(1, 1  => matches Ok(_); "Can sample vector with single element")]
    #[test_case(1024, 1024  => matches Err(ChalametPIRError::InvalidDimensionForVector); "Either number of rows or columns must be 1 in vector")]
    #[test_case(0, 1024  => matches Err(ChalametPIRError::InvalidDimensionForVector); "Number of rows in row vector must be 1")]
    #[test_case(1024, 0  => matches Err(ChalametPIRError::InvalidDimensionForVector); "Number of columns in column vector must be 1")]
    fn sampling_from_uniform_ternary_dist_works(num_rows: u32, num_cols: u32) -> Result<Matrix, ChalametPIRError> {
        Matrix::sample_from_uniform_ternary_dist(num_rows, num_cols)
    }

    #[test_case({let mut db: HashMap<&[u8], &[u8]> = HashMap::new(); db.insert(b"apple", b"red"); db} => matches Ok(_); "Should be able to encode non-empty database as matrix")]
    #[test_case(HashMap::new() => matches Err(ChalametPIRError::EmptyKVDatabase); "Can't encode empty database as matrix")]
    fn encoding_kv_database_as_matrix_using_3_wise_xor_filter(db: HashMap<&[u8], &[u8]>) -> Result<(Matrix, BinaryFuseFilter), ChalametPIRError> {
        const ARITY: u32 = 3;
        const MAT_ELEM_BIT_LEN: usize = 8;

        Matrix::from_kv_database::<ARITY>(db, MAT_ELEM_BIT_LEN, SERVER_SETUP_MAX_ATTEMPT_COUNT)
    }

    #[test_case({let mut db: HashMap<&[u8], &[u8]> = HashMap::new(); db.insert(b"apple", b"red"); db} => matches Ok(_); "Should be able to encode non-empty database as matrix")]
    #[test_case(HashMap::new() => matches Err(ChalametPIRError::EmptyKVDatabase); "Can't encode empty database as matrix")]
    fn encoding_kv_database_as_matrix_using_4_wise_xor_filter(db: HashMap<&[u8], &[u8]>) -> Result<(Matrix, BinaryFuseFilter), ChalametPIRError> {
        const ARITY: u32 = 4;
        const MAT_ELEM_BIT_LEN: usize = 8;

        Matrix::from_kv_database::<ARITY>(db, MAT_ELEM_BIT_LEN, SERVER_SETUP_MAX_ATTEMPT_COUNT)
    }

    #[test]
    fn serialized_matrix_can_be_deserialized() {
        const NUM_ATTEMPT_MATRIX_SERIALIZATIONS: usize = 100;
        const MIN_MATRIX_DIM: u32 = 1;
        const MAX_MATRIX_DIM: u32 = 1024;

        let mut rng = ChaCha8Rng::from_os_rng();

        let mut seed = [0u8; SEED_BYTE_LEN];
        rng.fill_bytes(&mut seed);

        let mut current_attempt_count = 0;
        while current_attempt_count < NUM_ATTEMPT_MATRIX_SERIALIZATIONS {
            let num_rows = rng.random_range(MIN_MATRIX_DIM..=MAX_MATRIX_DIM);
            let num_cols = rng.random_range(MIN_MATRIX_DIM..=MAX_MATRIX_DIM);

            let matrix_a = Matrix::generate_from_seed(num_rows, num_cols, &seed).expect("Matrix must be generated from seed");
            let matrix_a_bytes = matrix_a.to_bytes();
            let matrix_b = Matrix::from_bytes(&matrix_a_bytes).unwrap();

            assert_eq!(matrix_a, matrix_b);

            current_attempt_count += 1;
        }
    }

    #[test]
    fn validate_bits_per_entry_for_3_wise_xor_filter() {
        const ARITY: u32 = 3;
        const NUM_KV_PAIRS: usize = 1_000_000;
        const MAT_ELEM_BIT_LEN: usize = 10;
        const EXPECTED_BPE: f64 = (MAT_ELEM_BIT_LEN as f64) * 1.13; // From section 4 of ia.cr/2024/092

        let kv_db = generate_random_kv_database(NUM_KV_PAIRS);
        let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

        let (_, filter) = Matrix::from_kv_database::<ARITY>(kv_db_as_ref, MAT_ELEM_BIT_LEN, SERVER_SETUP_MAX_ATTEMPT_COUNT).unwrap();

        let computed_bpe = filter.bits_per_entry();
        assert!(computed_bpe <= EXPECTED_BPE.ceil());
    }

    #[test]
    fn validate_bits_per_entry_for_4_wise_xor_filter() {
        const ARITY: u32 = 4;
        const NUM_KV_PAIRS: usize = 1_000_000;
        const MAT_ELEM_BIT_LEN: usize = 10;
        const EXPECTED_BPE: f64 = (MAT_ELEM_BIT_LEN as f64) * 1.08; // From section 4 of ia.cr/2024/092

        let kv_db = generate_random_kv_database(NUM_KV_PAIRS);
        let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

        let (_, filter) = Matrix::from_kv_database::<ARITY>(kv_db_as_ref, MAT_ELEM_BIT_LEN, SERVER_SETUP_MAX_ATTEMPT_COUNT).unwrap();

        let computed_bpe = filter.bits_per_entry();
        assert!(computed_bpe <= EXPECTED_BPE.ceil());
    }

    #[test]
    fn row_wise_compressed_matrix_can_be_decompressed() {
        const ARITY: u32 = 3;

        const MIN_NUM_KV_PAIRS: usize = 1_000;
        const MAX_NUM_KV_PAIRS: usize = 10_000;

        const MIN_MAT_ELEM_BIT_LEN: usize = 4;
        const MAX_MAT_ELEM_BIT_LEN: usize = 14;

        let mut rng = ChaCha8Rng::from_os_rng();

        const NUM_TEST_ITERATIONS: usize = 1_000;
        let mut test_iter = 0;

        while test_iter < NUM_TEST_ITERATIONS {
            let num_kv_pairs = rng.random_range(MIN_NUM_KV_PAIRS..=MAX_NUM_KV_PAIRS);
            let mat_elem_bit_len = rng.random_range(MIN_MAT_ELEM_BIT_LEN..=MAX_MAT_ELEM_BIT_LEN);

            let kv_db = generate_random_kv_database(num_kv_pairs);
            let kv_db_as_ref = kv_db.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect::<HashMap<&[u8], &[u8]>>();

            let (db_mat, _) = Matrix::from_kv_database::<ARITY>(kv_db_as_ref.clone(), mat_elem_bit_len, SERVER_SETUP_MAX_ATTEMPT_COUNT)
                .expect("Must be able to encode key-value database as matrix");

            let compressed_matrix = db_mat.clone().row_wise_compress(mat_elem_bit_len).expect("Matrix compression must work");
            let decompressed_matrix = compressed_matrix
                .row_wise_decompress(mat_elem_bit_len, db_mat.num_cols())
                .expect("Matrix decompresson must work");

            assert_eq!(db_mat, decompressed_matrix);

            test_iter += 1;
        }
    }
}
