use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

pub struct BinaryFuseFilter {
    pub seed: [u8; 32],
    pub segment_length: u32,
    pub segment_count_length: u32,
    pub num_fingerprints: usize,
    pub filter_size: usize,
    pub mat_elem_bit_len: usize,
}

impl BinaryFuseFilter {
    pub fn construct_filter<'a>(
        db: &HashMap<&'a [u8], &[u8]>,
        arity: u32,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Option<(BinaryFuseFilter, Vec<u64>, Vec<u8>, HashMap<u64, &'a [u8]>)> {
        let filter_size = db.len();

        if filter_size == 0 {
            return None;
        }
        if !(arity == 3 || arity == 4) {
            return None;
        }

        let segment_length = segment_length(arity, filter_size as u32).min(1u32 << 18);

        let size_factor = size_factor(arity, filter_size as u32);
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
                let hashed_key = hash_of_key(key);
                let hash = mix256(&hashed_key, &seed);

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

                let (h0, h1, h2) = hash_batch(hash, segment_length, segment_count_length);

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

                    let (h0, h1, h2) = hash_batch(hash, segment_length, segment_count_length);

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
                    t2count[other_index1] ^= mod3(found + 1);
                    t2hash[other_index1] ^= hash;

                    let other_index2 = h012[(found + 2) as usize] as usize;
                    alone[qsize] = other_index2 as u32;
                    if (t2count[other_index2] >> 2) == 2 {
                        qsize += 1;
                    }

                    t2count[other_index2] -= 4;
                    t2count[other_index2] ^= mod3(found + 2);
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
                mat_elem_bit_len,
            },
            reverse_order,
            reverse_h,
            hash_to_key,
        ))
    }
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
    h = h.overflowing_mul(0xff51_afd7_ed55_8ccd).0;
    h ^= h >> 33;
    h = h.overflowing_mul(0xc4ce_b9fe_1a85_ec53).0;
    h ^= h >> 33;
    h
}

#[inline(always)]
pub const fn mix(key: u64, seed: u64) -> u64 {
    murmur64(key.overflowing_add(seed).0)
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
                .fold(0u64, |acc, seed_word| murmur64(acc.overflowing_add(mix(k, seed_word)).0))
        })
        .fold(0, |acc, r| acc.overflowing_add(r).0)
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
