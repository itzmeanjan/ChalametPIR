use sha3::{Digest, Sha3_256};

#[inline]
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

#[inline]
pub fn size_factor(arity: u32, size: u32) -> f64 {
    match arity {
        3 => 1.125_f64.max(0.875 + 0.25 * 1e6_f64.ln() / (size as f64).ln()),
        4 => 1.075_f64.max(0.77 + 0.305 * 6e5_f64.ln() / (size as f64).ln()),
        _ => 2.0,
    }
}

#[inline]
pub const fn mod3(x: u8) -> u8 {
    if x > 2 {
        x - 3
    } else {
        x
    }
}

/// Computes a 64-bit MurmurHash3-like hash from a 64-bit input.
/// See https://github.com/aappleby/smhasher/blob/0ff96f7835817a27d0487325b6c16033e2992eb5/src/MurmurHash3.cpp#L81-L90.
#[inline]
pub const fn murmur64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h *= 0xff51_afd7_ed55_8ccd;
    h ^= h >> 33;
    h *= 0xc4ce_b9fe_1a85_ec53;
    h ^= h >> 33;

    return h;
}

#[inline]
pub const fn mix(key: u64, seed: u64) -> u64 {
    murmur64(key.overflowing_add(seed).0)
}

#[inline]
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
