use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Sha3_256};
use std::{cmp::min, collections::HashMap};

pub struct BinaryFuseFilter {
    pub seed: [u8; 32],
    pub segment_length: u32,
    pub segment_count_length: u32,
    pub num_fingerprints: usize,
    pub filter_size: usize,
}

impl BinaryFuseFilter {
    pub fn construct_filter<'a>(
        db: &HashMap<&'a [u8], &[u8]>,
        arity: u32,
        max_attempt_count: usize,
    ) -> Option<(BinaryFuseFilter, Vec<u64>, Vec<u8>, HashMap<u64, &'a [u8]>)> {
        let filter_size = db.len();

        if filter_size == 0 {
            return None;
        }
        if !(arity == 3 || arity == 4) {
            return None;
        }

        let segment_length = Self::segment_length(arity, filter_size as u32).min(1u32 << 18);

        let size_factor = Self::size_factor(arity, filter_size as u32);
        let capacity = if filter_size > 1 {
            ((filter_size as f64) * size_factor).round() as u32
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

        let mut alone = vec![0u32; num_fingerprints];
        let mut t2count = vec![0u8; num_fingerprints];
        let mut t2hash = vec![0u64; num_fingerprints];
        let mut reverse_h = vec![0u8; filter_size];
        let mut reverse_order = vec![0u64; filter_size + 1];
        reverse_order[filter_size] = 1;

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
                start_pos[i] = (((i as u64) * (filter_size as u64)) >> block_bits) as usize;
            }

            for &key in db.keys() {
                let hashed_key = Self::hash_of_key(key);
                let hash = Self::mix256(&hashed_key, &seed);

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
            for i in 0..filter_size {
                let hash = reverse_order[i];

                let (h0, h1, h2) = Self::hash_batch(hash, segment_length, segment_count_length);

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
                reverse_order[..filter_size].fill(0);
                t2count.fill(0);
                t2hash.fill(0);

                continue;
            }

            let mut qsize = 0;
            for i in 0..num_fingerprints {
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

                    let (h0, h1, h2) = Self::hash_batch(hash, segment_length, segment_count_length);

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
                    t2count[other_index1] ^= Self::mod3(found + 1);
                    t2hash[other_index1] ^= hash;

                    let other_index2 = h012[(found + 2) as usize] as usize;
                    alone[qsize] = other_index2 as u32;
                    if (t2count[other_index2] >> 2) == 2 {
                        qsize += 1;
                    }

                    t2count[other_index2] -= 4;
                    t2count[other_index2] ^= Self::mod3(found + 2);
                    t2hash[other_index2] ^= hash;
                }
            }

            if stack_size == filter_size {
                ultimate_size = stack_size;
                done = true;

                break;
            }

            reverse_order[..filter_size].fill(0);
            t2count.fill(0);
            t2hash.fill(0);
        }

        if !done {
            return None;
        }

        Some((
            BinaryFuseFilter {
                seed,
                segment_length,
                segment_count_length,
                num_fingerprints,
                filter_size: ultimate_size,
            },
            reverse_order,
            reverse_h,
            hash_to_key,
        ))
    }

    #[inline(always)]
    pub fn segment_length(arity: u32, size: u32) -> u32 {
        if size == 0 {
            return 4;
        }

        match arity {
            3 => 1u32 << ((size as f64).ln() / 3.33_f64.ln() + 2.25).floor() as usize,
            4 => 1u32 << ((size as f64).ln() / 2.91_f64.ln() - 0.5).floor() as usize,
            _ => 65536,
        }
    }

    #[inline(always)]
    pub fn size_factor(arity: u32, size: u32) -> f64 {
        match arity {
            3 => 1.125_f64.max(0.875 + 0.25 * 1e6_f64.ln() / (size as f64).ln()),
            4 => 1.075_f64.max(0.77 + 0.305 * 6e5_f64.ln() / (size as f64).ln()),
            _ => 2.0,
        }
    }

    #[inline(always)]
    pub const fn mod3(x: u8) -> u8 {
        if x > 2 {
            x - 3
        } else {
            x
        }
    }

    /// Computes a 64-bit MurmurHash3-like hash from a 64-bit input.
    /// See https://github.com/aappleby/smhasher/blob/0ff96f7835817a27d0487325b6c16033e2992eb5/src/MurmurHash3.cpp#L81-L90.
    #[inline(always)]
    pub const fn murmur64(mut h: u64) -> u64 {
        h ^= h >> 33;
        h *= 0xff51_afd7_ed55_8ccd;
        h ^= h >> 33;
        h *= 0xc4ce_b9fe_1a85_ec53;
        h ^= h >> 33;

        return h;
    }

    #[inline(always)]
    pub const fn mix(key: u64, seed: u64) -> u64 {
        Self::murmur64(key.overflowing_add(seed).0)
    }

    #[inline(always)]
    pub fn mix256<'a>(key: &[u64; 4], seed: &[u8; 32]) -> u64 {
        let seed_words = [
            u64::from_le_bytes(seed[..8].try_into().unwrap()),
            u64::from_le_bytes(seed[8..16].try_into().unwrap()),
            u64::from_le_bytes(seed[16..24].try_into().unwrap()),
            u64::from_le_bytes(seed[24..].try_into().unwrap()),
        ];

        key.into_iter()
            .map(|&k| {
                seed_words
                    .into_iter()
                    .fold(0u64, |acc, seed_word| Self::murmur64(acc.overflowing_add(Self::mix(k, seed_word)).0))
            })
            .fold(0, |acc, r| acc.overflowing_add(r).0)
    }

    #[inline(always)]
    pub fn hash_of_key(key: &[u8]) -> [u64; 4] {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        let digest_bytes = hasher.finalize();

        [
            u64::from_le_bytes(digest_bytes[..8].try_into().unwrap()),
            u64::from_le_bytes(digest_bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(digest_bytes[16..24].try_into().unwrap()),
            u64::from_le_bytes(digest_bytes[24..].try_into().unwrap()),
        ]
    }

    #[inline]
    pub const fn hash_batch(hash: u64, segment_length: u32, segment_count_length: u32) -> (u32, u32, u32) {
        let segment_length_mask = segment_length - 1;
        let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;

        let h0 = hi as u32;
        let mut h1 = h0 + segment_length;
        let mut h2 = h1 + segment_length;

        h1 ^= ((hash >> 18) as u32) & segment_length_mask;
        h2 ^= (hash as u32) & segment_length_mask;

        (h0, h1, h2)
    }
}

#[inline]
pub fn encode_kv_as_row(key: &[u8], value: &[u8], mat_elem_bit_len: usize, num_cols: usize) -> Vec<u32> {
    let hashed_key = {
        let mut hasher = Sha3_256::new();
        hasher.update(key);

        let mut hashed_key = [0u8; 32];
        hasher.finalize_into((&mut hashed_key).into());
        hashed_key
    };

    let mut row = vec![0u32; num_cols];
    let mut row_offset = 0;

    let mat_elem_mask = (1u64 << mat_elem_bit_len) - 1;

    let mut buffer = 0u64;
    let mut buf_num_bits = 0usize;

    let mut byte_offset = 0;
    while byte_offset < hashed_key.len() {
        let remaining_num_bytes = hashed_key.len() - byte_offset;

        let unset_num_bits = 64 - buf_num_bits;
        let fillable_num_bits = unset_num_bits & 8usize.wrapping_neg();
        let fillable_num_bytes = min(fillable_num_bits / 8, remaining_num_bytes);
        let read_num_bits = fillable_num_bytes * 8;

        let till_key_bytes_idx = byte_offset + fillable_num_bytes;
        let read_word = u64_from_le_bytes(&hashed_key[byte_offset..till_key_bytes_idx]);
        byte_offset = till_key_bytes_idx;

        buffer |= read_word << buf_num_bits;
        buf_num_bits += read_num_bits;

        let fillable_num_elems = buf_num_bits / mat_elem_bit_len;

        for elem_idx in 0..fillable_num_elems {
            let elem = (buffer & mat_elem_mask) as u32;
            row[row_offset + elem_idx] = elem;

            buffer >>= mat_elem_bit_len;
            buf_num_bits -= mat_elem_bit_len;
        }

        row_offset += fillable_num_elems;
    }

    byte_offset = 0;
    while byte_offset < value.len() {
        let remaining_num_bytes = value.len() - byte_offset;

        let unset_num_bits = 64 - buf_num_bits;
        let fillable_num_bits = unset_num_bits & 8usize.wrapping_neg();
        let fillable_num_bytes = min(fillable_num_bits / 8, remaining_num_bytes);
        let read_num_bits = fillable_num_bytes * 8;

        let till_value_bytes_idx = byte_offset + fillable_num_bytes;
        let read_word = u64_from_le_bytes(&value[byte_offset..till_value_bytes_idx]);
        byte_offset = till_value_bytes_idx;

        buffer |= read_word << buf_num_bits;
        buf_num_bits += read_num_bits;

        let fillable_num_elems = buf_num_bits / mat_elem_bit_len;

        for elem_idx in 0..fillable_num_elems {
            let elem = (buffer & mat_elem_mask) as u32;
            row[row_offset + elem_idx] = elem;

            buffer >>= mat_elem_bit_len;
            buf_num_bits -= mat_elem_bit_len;
        }

        row_offset += fillable_num_elems;
    }

    let boundary_mark = 0x81;
    buffer |= boundary_mark << buf_num_bits;
    buf_num_bits += 8;

    while buf_num_bits > 0 {
        let readble_num_bits = min(buf_num_bits, mat_elem_bit_len);

        let elem = (buffer & mat_elem_mask) as u32;
        row[row_offset] = elem;

        buffer >>= readble_num_bits;
        buf_num_bits -= readble_num_bits;
        row_offset += 1;
    }

    row
}

#[inline]
pub fn decode_kv_from_row(row: &[u32], mat_elem_bit_len: usize) -> Option<Vec<u8>> {
    let num_extractable_bits = (row.len() * mat_elem_bit_len) & 8usize.wrapping_neg();
    let num_bytes_to_represent_kv = num_extractable_bits / 8;

    let mut kv = vec![0u8; num_bytes_to_represent_kv];
    let mat_elem_mask = (1u32 << mat_elem_bit_len) - 1;

    let mut buffer = 0u64;
    let mut buf_num_bits = 0;

    let mut row_offset = 0;
    let mut byte_offset = 0;

    while row_offset < row.len() {
        let remaining_num_bits = num_extractable_bits - (byte_offset * 8 + buf_num_bits);
        let selected_bits = row[row_offset] & mat_elem_mask;

        buffer |= (selected_bits as u64) << buf_num_bits;
        buf_num_bits += min(mat_elem_bit_len, remaining_num_bits);

        let decodable_num_bits = buf_num_bits & 8usize.wrapping_neg();
        let decodable_num_bytes = decodable_num_bits / 8;

        u64_to_le_bytes(buffer, &mut kv[byte_offset..(byte_offset + decodable_num_bytes)]);

        buffer >>= decodable_num_bits;
        buf_num_bits -= decodable_num_bits;

        row_offset += 1;
        byte_offset += decodable_num_bytes;
    }

    let boundary_mark = 0x81;
    match kv.iter().rev().position(|&v| v == boundary_mark) {
        Some(boundary_idx_from_back) => {
            let last_idx_of_kv = kv.len() - 1;
            let boundary_idx_from_front = last_idx_of_kv - boundary_idx_from_back;

            let is_zeroed_post_boundary = kv[boundary_idx_from_front + 1..].iter().fold(true, |acc, &cur| acc & (cur == 0));

            if is_zeroed_post_boundary && boundary_idx_from_front > 32 {
                kv.truncate(boundary_idx_from_front);
                Some(kv)
            } else {
                None
            }
        }
        None => None,
    }
}

#[inline(always)]
pub fn u64_from_le_bytes(bytes: &[u8]) -> u64 {
    let mut word = 0;
    let readable_num_bytes = min(bytes.len(), std::mem::size_of::<u64>());

    for i in 0..readable_num_bytes {
        word |= (bytes[i] as u64) << (i * 8);
    }

    word
}

#[inline(always)]
pub fn u64_to_le_bytes(word: u64, bytes: &mut [u8]) {
    let writable_num_bytes = min(bytes.len(), std::mem::size_of::<u64>());

    for i in 0..writable_num_bytes {
        bytes[i] = (word >> i * 8) as u8;
    }
}

#[cfg(test)]
mod test {
    use crate::binary_fuse_filter::{decode_kv_from_row, encode_kv_as_row};
    use rand::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use sha3::{Digest, Sha3_256};

    #[test]
    fn encode_kv_as_row_and_recover() {
        const MIN_KEY_BYTE_LEN: usize = 1;
        const MAX_KEY_BYTE_LEN: usize = 256;

        const MIN_VALUE_BYTE_LEN: usize = 1;
        const MAX_VALUE_BYTE_LEN: usize = 256;

        const MIN_MAT_ELEM_BIT_LEN: usize = 1;
        const MAX_MAT_ELEM_BIT_LEN: usize = 10;

        let mut rng = ChaCha8Rng::from_entropy();

        for key_byte_len in MIN_KEY_BYTE_LEN..MAX_KEY_BYTE_LEN {
            for value_byte_len in MIN_VALUE_BYTE_LEN..MAX_VALUE_BYTE_LEN {
                for mat_elem_bit_len in MIN_MAT_ELEM_BIT_LEN..MAX_MAT_ELEM_BIT_LEN {
                    let mut key = vec![0u8; key_byte_len];
                    let mut value = vec![0u8; value_byte_len];

                    rng.fill_bytes(&mut key);
                    rng.fill_bytes(&mut value);

                    let hashed_key = {
                        let mut hasher = Sha3_256::new();
                        hasher.update(&key);

                        let mut hashed_key = [0u8; 32];
                        hasher.finalize_into((&mut hashed_key).into());
                        hashed_key
                    };

                    let actual_encoded_kv_len = (hashed_key.len() * 8 + (value.len() + 1) * 8).div_ceil(mat_elem_bit_len);
                    let max_encoded_kv_len = (hashed_key.len() * 8 + (2 * value.len() + 1) * 8).div_ceil(mat_elem_bit_len);

                    for encoded_kv_len in actual_encoded_kv_len..max_encoded_kv_len {
                        let row = encode_kv_as_row(&key, &value, mat_elem_bit_len, encoded_kv_len);
                        let decoded_kv = decode_kv_from_row(&row, mat_elem_bit_len).expect("Must be able to decode successfully !");

                        assert_eq!(
                            hashed_key,
                            decoded_kv[..hashed_key.len()],
                            "key_len = {}, value_len = {}, mat_elem_bit_len = {}",
                            key_byte_len,
                            value_byte_len,
                            mat_elem_bit_len
                        );
                        assert_eq!(
                            value,
                            decoded_kv[hashed_key.len()..],
                            "key_len = {}, value_len = {}, mat_elem_bit_len = {}",
                            key_byte_len,
                            value_byte_len,
                            mat_elem_bit_len
                        );
                    }
                }
            }
        }
    }
}
