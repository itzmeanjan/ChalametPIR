use sha3::{Digest, Sha3_256};
use std::cmp::min;

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
    murmur64(key.overflowing_add(seed).0)
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
            seed_words.into_iter().fold(0u64, |acc, seed_word| {
                murmur64(acc.overflowing_add(mix(k, seed_word)).0)
            })
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
pub const fn hash_batch(
    hash: u64,
    segment_length: u32,
    segment_count_length: u32,
) -> (u32, u32, u32) {
    let segment_length_mask = segment_length - 1;
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;

    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;

    h1 ^= ((hash >> 18) as u32) & segment_length_mask;
    h2 ^= (hash as u32) & segment_length_mask;

    (h0, h1, h2)
}

#[inline]
pub fn encode_kv_as_row(
    key: &[u8],
    value: &[u8],
    mat_elem_bit_len: usize,
    num_cols: usize,
) -> Vec<u32> {
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

    if (buf_num_bits > 0) && (row_offset < num_cols) {
        row[row_offset] = (buffer & mat_elem_mask) as u32;
    }

    row
}

#[inline]
pub fn decode_kv_as_row(row: &[u32], mat_elem_bit_len: usize) -> Vec<u8> {
    let num_extractable_bits_from_row = row.len() * mat_elem_bit_len;
    let num_bytes_to_represent_kv = num_extractable_bits_from_row / 8;
    let num_bits_to_be_extracted = num_bytes_to_represent_kv * 8;

    let mut kv = vec![0u8; num_bytes_to_represent_kv];
    let mat_elem_mask = (1u32 << mat_elem_bit_len) - 1;

    let mut buffer = 0u64;
    let mut buf_num_bits = 0;

    let mut row_offset = 0;
    let mut byte_offset = 0;

    while row_offset < row.len() {
        let remaining_num_bits = num_bits_to_be_extracted - byte_offset * 8 + buf_num_bits;
        let selected_bits = row[row_offset] & mat_elem_mask;

        buffer |= (selected_bits as u64) << buf_num_bits;
        buf_num_bits += min(mat_elem_bit_len, remaining_num_bits);

        let decodable_num_bits = buf_num_bits & 8usize.wrapping_neg();
        let decodable_num_bytes = decodable_num_bits / 8;

        u64_to_le_bytes(
            buffer,
            &mut kv[byte_offset..(byte_offset + decodable_num_bytes)],
        );

        buffer >>= decodable_num_bits;
        buf_num_bits -= decodable_num_bits;

        row_offset += 1;
        byte_offset += decodable_num_bytes;
    }

    kv
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
