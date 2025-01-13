use crate::binary_fuse_filter;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
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
                mat.elems[local_idx] =
                    u32::from_le_bytes(buffer[buf_offset..(buf_offset + 4)].try_into().unwrap());

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
    ) -> Option<Matrix> {
        let num_db_entry = db.len();

        if num_db_entry == 0 {
            return None;
        }
        if !(arity == 3 || arity == 4) {
            return None;
        }

        let segment_length =
            binary_fuse_filter::segment_length(arity, num_db_entry as u32).min(1u32 << 18);

        let size_factor = binary_fuse_filter::size_factor(arity, num_db_entry as u32);
        let capacity = if num_db_entry > 1 {
            ((num_db_entry as f64) * size_factor).round() as u32
        } else {
            0
        };

        let init_segment_count = (capacity + segment_length - 1) / segment_length;
        let (num_fingerprints, segment_count) = {
            let array_len = init_segment_count * segment_length;
            let segment_count: u32 = {
                let proposed = (array_len + segment_length - 1) / segment_length;
                if proposed < arity {
                    1
                } else {
                    proposed - (arity - 1)
                }
            };
            let array_len: u32 = (segment_count + arity - 1) * segment_length;
            (array_len as usize, segment_count)
        };
        let segment_count_length = segment_count * segment_length;

        let capacity = num_fingerprints;
        let mut alone = vec![0u32; num_fingerprints];
        let mut t2count = vec![0u8; num_fingerprints];
        let mut t2hash = vec![0u64; num_fingerprints];
        let mut reverse_h = vec![0u8; num_db_entry];
        let mut reverse_order = vec![0u64; num_db_entry + 1];
        reverse_order[num_db_entry] = 1;

        let mut hash_to_key = HashMap::new();

        let block_bits = {
            let mut block_bits = 1;
            while (1 << block_bits) < segment_count {
                block_bits += 1;
            }
            block_bits
        };
        let block_bits_mask = (1 << block_bits) - 1;

        let start_pos_len: usize = 1 << block_bits;
        let mut start_pos = vec![0usize; start_pos_len];

        let mut h012 = [0u32; 5];

        let mut done = false;
        let mut ultimate_size = 0;

        let mut seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_entropy();

        for _ in 0..max_attempt_count {
            rng.fill_bytes(&mut seed);

            for i in 0..start_pos_len {
                start_pos[i] = (((i as u64) * (num_db_entry as u64)) >> block_bits) as usize;
            }

            for key in db.keys() {
                let hashed_key = binary_fuse_filter::hash_of_key(key);
                let hash = binary_fuse_filter::mix256(&hashed_key, &seed);

                let mut segment_index = hash >> (64 - block_bits);
                while reverse_order[start_pos[segment_index as usize] as usize] != 0 {
                    segment_index += 1;
                    segment_index &= block_bits_mask;
                }

                reverse_order[start_pos[segment_index as usize] as usize] = hash;
                start_pos[segment_index as usize] += 1;

                hash_to_key.insert(hash, key);
            }

            let mut error = false;
            for i in 0..num_db_entry {
                let hash = reverse_order[i];

                let (h0, h1, h2) =
                    binary_fuse_filter::hash_batch(hash, segment_length, segment_count_length);

                let (h0, h1, h2) = (h0 as usize, h1 as usize, h2 as usize);

                t2count[h0] += 4;
                t2hash[h0] ^= hash;

                t2count[h1] += 4;
                t2count[h1] ^= 1;
                t2hash[h1] ^= hash;

                t2count[h2] += 4;
                t2count[h2] ^= 2;
                t2hash[h2] ^= hash;

                error = t2count[h0] < 4 || t2count[h1] < 4 || t2count[h2] < 4;
            }

            if error {
                reverse_order[..num_db_entry].fill(0);
                t2count.fill(0);
                t2hash.fill(0);

                continue;
            }

            let mut qsize = 0;
            for i in 0..capacity {
                alone[qsize] = i as u32;
                if (t2count[i] >> 2) == 1 {
                    qsize += 1;
                }
            }

            let mut stack_size = 0;
            while qsize > 0 {
                qsize -= 1;

                let index = alone[qsize] as usize;
                if (t2count[index] >> 2) == 1 {
                    let hash = t2hash[index];
                    let found: u8 = t2count[index] & 3;

                    reverse_h[stack_size] = found;
                    reverse_order[stack_size] = hash;
                    stack_size += 1;

                    let (h0, h1, h2) =
                        binary_fuse_filter::hash_batch(hash, segment_length, segment_count_length);

                    h012[1] = h1;
                    h012[2] = h2;
                    h012[3] = h0;
                    h012[4] = h012[1];

                    let other_index1 = h012[(found + 1) as usize] as usize;
                    alone[qsize] = other_index1 as u32;
                    if (t2count[other_index1] >> 2) == 2 {
                        qsize += 1;
                    }

                    t2count[other_index1] -= 4;
                    t2count[other_index1] ^= binary_fuse_filter::mod3(found + 1);
                    t2hash[other_index1] ^= hash;

                    let other_index2 = h012[(found + 2) as usize] as usize;
                    alone[qsize] = other_index2 as u32;
                    if (t2count[other_index2] >> 2) == 2 {
                        qsize += 1;
                    }

                    t2count[other_index2] -= 4;
                    t2count[other_index2] ^= binary_fuse_filter::mod3(found + 2);
                    t2hash[other_index2] ^= hash;
                }
            }

            if stack_size == num_db_entry {
                ultimate_size = stack_size;
                done = true;

                break;
            }

            reverse_order[..num_db_entry].fill(0);
            t2count.fill(0);
            t2hash.fill(0);
        }

        if !done {
            return None;
        }

        const HASHED_KEY_BIT_LEN: usize = 256;
        const HASHED_KEY_BYTE_LEN: usize = HASHED_KEY_BIT_LEN / 8;

        let max_value_byte_len = db.values().map(|v| v.len()).max()?;
        let max_value_bit_len = max_value_byte_len * 8;

        let rows = num_fingerprints;
        let cols: usize = (HASHED_KEY_BIT_LEN + max_value_bit_len + 8).div_ceil(mat_elem_bit_len);

        let mut mat = Matrix::new(rows, cols)?;
        let mat_elem_mask = (1u32 << mat_elem_bit_len) - 1;

        for i in (0..ultimate_size).rev() {
            let hash = reverse_order[i];
            let key = **hash_to_key.get(&hash)?;
            let value = *db.get(key)?;

            let (h0, h1, h2) =
                binary_fuse_filter::hash_batch(hash, segment_length, segment_count_length);

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
                    let mask =
                        (binary_fuse_filter::mix(hash, elem_idx as u64) as u32) & mat_elem_mask;
                    elem.wrapping_sub(mask) & mat_elem_mask
                })
                .collect::<Vec<u32>>();
            mat.elems[mat_row_idx0 * cols..].copy_from_slice(&elems);
        }

        Some(mat)
    }
}

mod test {
    #[test]
    fn test_mat_generation() {
        let seed = [0u8; 32];
        let m = super::Matrix::generate_from_seed(1024, 1024, &seed).unwrap();
    }
}
