use crate::binary_fuse_filter::{self, BinaryFuseFilter};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use std::{cmp::min, collections::HashMap};

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
        match binary_fuse_filter::BinaryFuseFilter::construct_filter(&db, arity, max_attempt_count) {
            Some((filter, reverse_order, reverse_h, hash_to_key)) => {
                const HASHED_KEY_BIT_LEN: usize = 256;
                const HASHED_KEY_BYTE_LEN: usize = HASHED_KEY_BIT_LEN / 8;

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

                    let (h0, h1, h2) = BinaryFuseFilter::hash_batch(hash, filter.segment_length, filter.segment_count_length);

                    let found = reverse_h[i] as usize;
                    h012[0] = h0;
                    h012[1] = h1;
                    h012[2] = h2;
                    h012[3] = h012[0];
                    h012[4] = h012[1];

                    let row = binary_fuse_filter::encode_kv_as_row(key, value, mat_elem_bit_len, cols);

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
                            let mask = (BinaryFuseFilter::mix(hash, elem_idx as u64) as u32) & mat_elem_mask;
                            elem.wrapping_sub(mask) & mat_elem_mask
                        })
                        .collect::<Vec<u32>>();
                    mat.elems[mat_row_idx0 * cols..].copy_from_slice(&elems);
                }

                Some((mat, filter))
            }
            None => None,
        }
    }
}

mod test {
    #[test]
    fn test_mat_generation() {
        let seed = [0u8; 32];
        let m = super::Matrix::generate_from_seed(1024, 1024, &seed).unwrap();
    }
}
