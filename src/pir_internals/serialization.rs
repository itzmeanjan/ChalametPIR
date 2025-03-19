use super::{branch_opt_util, error::ChalametPIRError, params};
use std::cmp::min;
use turboshake::TurboShake128;

/// Encodes a key-value pair into a row of 32-bit unsigned integers.
///
/// The key is hashed using TurboSHAKE128 xof, and both the 32 -bytes hashed key and value are interleaved into the row.
/// A boundary marker is added to denote the end of valid value bytes. Remaining elements of the resulting row,
/// if any, are filled with zeros.
///
/// # Arguments
///
/// * `key` - The key to encode.
/// * `value` - The value to encode.
/// * `mat_elem_bit_len` - The number of bits per element in the resulting row vector.
/// * `num_cols` - The number of columns in the matrix (the length of the row).
///
/// # Returns
///
/// A vector of 32-bit unsigned integers representing the encoded key-value pair.
#[inline]
pub fn encode_kv_as_row(key: &[u8], value: &[u8], mat_elem_bit_len: usize, num_cols: u32) -> Vec<u32> {
    let hashed_key = {
        let mut hasher = TurboShake128::default();
        hasher.absorb(key);
        hasher.finalize::<{ TurboShake128::DEFAULT_DOMAIN_SEPARATOR }>();

        let mut hashed_key = [0u8; params::HASHED_KEY_BYTE_LEN];
        hasher.squeeze(&mut hashed_key);

        hashed_key
    };

    let mut row = vec![0u32; num_cols as usize];
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

/// Decodes a key-value pair from a row of 32-bit unsigned integers.
///
/// The key-value pair is interleaved in the row. A boundary marker is used to denote where actual value bytes end.
/// The function returns an error if the row does not contain a valid key-value pair or if there is an error during decoding.
///
/// # Arguments
///
/// * `row` - The row of 32-bit unsigned integers to decode.
/// * `mat_elem_bit_len` - The number of bits per element in the row vector.
///
/// # Returns
///
/// A Result containing a vector of bytes representing the decoded key-value pair (hashed-key followed by value), or an error.
#[inline]
pub fn decode_kv_from_row(row: &[u32], mat_elem_bit_len: usize) -> Result<Vec<u8>, ChalametPIRError> {
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

            if branch_opt_util::likely(is_zeroed_post_boundary && boundary_idx_from_front > 32) {
                kv.truncate(boundary_idx_from_front);
                Ok(kv)
            } else {
                Err(ChalametPIRError::RowNotDecodable)
            }
        }
        None => {
            branch_opt_util::cold();
            Err(ChalametPIRError::RowNotDecodable)
        }
    }
}

/// Converts a slice of bytes into a u64 in little-endian byte order.
///
/// Reads at most 8 bytes from the input slice. If the slice is shorter than 8 bytes, it reads only the available bytes,
/// while setting other bytes to 0. The function handles cases where the input slice is empty.
///
/// # Arguments
///
/// * `bytes` - The slice of bytes to convert.
///
/// # Returns
///
/// A u64 representing the bytes in little-endian byte order.
#[inline(always)]
pub fn u64_from_le_bytes(bytes: &[u8]) -> u64 {
    let mut word = 0;
    let readable_num_bytes = min(bytes.len(), std::mem::size_of::<u64>());

    for (idx, &byte) in bytes.iter().enumerate().take(readable_num_bytes) {
        word |= (byte as u64) << (idx * 8);
    }

    word
}

/// Converts a u64 into a slice of bytes in little-endian byte order.
///
/// Writes at most 8 bytes to the output slice. If the slice is shorter than 8 bytes, it writes only the those many bytes.
/// The function handles cases where the output slice is empty.
///
/// # Arguments
///
/// * `word` - The u64 to convert.
/// * `bytes` - The mutable slice of bytes to write to.
#[inline(always)]
pub fn u64_to_le_bytes(word: u64, bytes: &mut [u8]) {
    let writable_num_bytes = min(bytes.len(), std::mem::size_of::<u64>());

    for (idx, byte) in bytes.iter_mut().enumerate().take(writable_num_bytes) {
        *byte = (word >> (idx * 8)) as u8;
    }
}

#[cfg(test)]
mod test {
    use crate::pir_internals::{
        params,
        serialization::{decode_kv_from_row, encode_kv_as_row},
    };
    use rand::prelude::*;
    use rand_chacha::ChaCha8Rng;
    use turboshake::TurboShake128;

    #[test]
    fn encode_kv_as_row_and_recover() {
        const MIN_KEY_BYTE_LEN: usize = 1;
        const MAX_KEY_BYTE_LEN: usize = 32;

        const MIN_VALUE_BYTE_LEN: usize = 1;
        const MAX_VALUE_BYTE_LEN: usize = 64;

        const MIN_MAT_ELEM_BIT_LEN: usize = 7;
        const MAX_MAT_ELEM_BIT_LEN: usize = 11;

        let mut rng = ChaCha8Rng::from_os_rng();

        for key_byte_len in MIN_KEY_BYTE_LEN..=MAX_KEY_BYTE_LEN {
            for value_byte_len in MIN_VALUE_BYTE_LEN..=MAX_VALUE_BYTE_LEN {
                for mat_elem_bit_len in MIN_MAT_ELEM_BIT_LEN..=MAX_MAT_ELEM_BIT_LEN {
                    let mut key = vec![0u8; key_byte_len];
                    let mut value = vec![0u8; value_byte_len];

                    rng.fill_bytes(&mut key);
                    rng.fill_bytes(&mut value);

                    let hashed_key = {
                        let mut hasher = TurboShake128::default();
                        hasher.absorb(&key);
                        hasher.finalize::<{ TurboShake128::DEFAULT_DOMAIN_SEPARATOR }>();

                        let mut hashed_key = [0u8; params::HASHED_KEY_BYTE_LEN];
                        hasher.squeeze(&mut hashed_key);

                        hashed_key
                    };

                    let actual_encoded_kv_len = (hashed_key.len() * 8 + (value.len() + 1) * 8).div_ceil(mat_elem_bit_len) as u32;
                    let max_encoded_kv_len = (hashed_key.len() * 8 + (2 * value.len() + 1) * 8).div_ceil(mat_elem_bit_len) as u32;

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
