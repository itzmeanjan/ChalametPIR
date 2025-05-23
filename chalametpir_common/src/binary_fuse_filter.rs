use std::collections::HashMap;

use super::{branch_opt_util, error::ChalametPIRError, params};
use turboshake::TurboShake128;

#[cfg(feature = "wasm")]
use tinyrand::{Rand, StdRand};

#[cfg(not(feature = "wasm"))]
use rand::prelude::*;
#[cfg(not(feature = "wasm"))]
use rand_chacha::ChaCha20Rng;

#[derive(Clone, Debug)]
pub struct BinaryFuseFilter {
    pub seed: [u8; 32],
    pub arity: u32,
    pub segment_length: u32,
    pub segment_count_length: u32,
    pub num_fingerprints: usize,
    pub filter_size: usize,
    pub mat_elem_bit_len: usize,
}

type BinaryFuseFilterIntermediateStageResult<'a> = (BinaryFuseFilter, Vec<u64>, Vec<u8>, HashMap<u64, &'a [u8]>);

impl BinaryFuseFilter {
    /// Constructs a 3-wise xor Binary Fuse Filter. This implementation collects inspiration from https://github.com/FastFilter/fastfilter_cpp/blob/5df1dc5063702945f6958e4bda445dd082aed366/src/xorfilter/3wise_xor_binary_fuse_filter_lowmem.h.
    ///
    /// # Arguments
    ///
    /// * `db` - A HashMap, representing a Key-Value database, containing the data to be inserted into the filter.
    /// * `mat_elem_bit_len` - The number of bits per element in the filter's matrix.
    /// * `max_attempt_count` - The maximum number of attempts to construct the filter before giving up.
    ///
    /// # Returns
    ///
    /// A Result containing the constructed BinaryFuseFilter, the reverse order of the inserted data, the reverse hash values, and a mapping from hash values to keys.
    /// Returns an error if the filter could not be constructed within the given number of attempts or the key-value database is empty.
    pub fn construct_3_wise_xor_filter<'a>(
        db: &HashMap<&'a [u8], &[u8]>,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Result<BinaryFuseFilterIntermediateStageResult<'a>, ChalametPIRError> {
        const ARITY: u32 = 3;

        let db_size = db.len();
        if branch_opt_util::unlikely(db_size == 0) {
            return Err(ChalametPIRError::EmptyKVDatabase);
        }

        let segment_length = segment_length::<ARITY>(db_size as u32).min(1u32 << 18);

        let size_factor = size_factor::<ARITY>(db_size as u32);
        let capacity = if db_size > 1 { ((db_size as f64) * size_factor).round() as u32 } else { 0 };

        let init_segment_count = capacity.div_ceil(segment_length);
        let (num_fingerprints, segment_count) = {
            let array_len = init_segment_count * segment_length;
            let segment_count: u32 = {
                let proposed = array_len.div_ceil(segment_length);
                if proposed < ARITY { 1 } else { proposed - (ARITY - 1) }
            };
            let array_len: u32 = (segment_count + ARITY - 1) * segment_length;
            (array_len as usize, segment_count)
        };
        let segment_count_length = segment_count * segment_length;

        let mut alone = vec![0u32; num_fingerprints];
        let mut t2count = vec![0u8; num_fingerprints];
        let mut t2hash = vec![0u64; num_fingerprints];
        let mut reverse_h = vec![0u8; db_size];
        let mut reverse_order = vec![0u64; db_size + 1];
        reverse_order[db_size] = 1;

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

        #[cfg(feature = "wasm")]
        let mut rng = StdRand::default();
        #[cfg(not(feature = "wasm"))]
        let mut rng = ChaCha20Rng::from_os_rng();

        for _ in 0..max_attempt_count {
            #[cfg(not(feature = "wasm"))]
            rng.fill_bytes(&mut seed);
            #[cfg(feature = "wasm")]
            seed.fill_with(|| rng.next_u32() as u8);

            for (idx, val) in start_pos.iter_mut().enumerate() {
                *val = (((idx as u64) * (db_size as u64)) >> block_bits) as usize;
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
            for &hash in reverse_order.iter().take(db_size) {
                let (h0, h1, h2) = hash_batch_for_3_wise_xor_filter(hash, segment_length, segment_count_length);
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
                reverse_order[..db_size].fill(0);
                t2count.fill(0);
                t2hash.fill(0);

                continue;
            }

            let mut qsize = 0;
            for (idx, &count) in t2count.iter().enumerate().take(num_fingerprints) {
                alone[qsize] = idx as u32;
                if (count >> 2) == 1 {
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

                    let (h0, h1, h2) = hash_batch_for_3_wise_xor_filter(hash, segment_length, segment_count_length);

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

            if stack_size == db_size {
                ultimate_size = stack_size;
                done = true;

                break;
            }

            reverse_order[..db_size].fill(0);
            t2count.fill(0);
            t2hash.fill(0);
        }

        if branch_opt_util::unlikely(!done) {
            return Err(ChalametPIRError::ExhaustedAllAttemptsToBuild3WiseXorFilter(max_attempt_count));
        }

        Ok((
            BinaryFuseFilter {
                seed,
                arity: ARITY,
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

    /// Constructs a 4-wise xor Binary Fuse Filter. This implementation collects inspiration from https://github.com/FastFilter/fastfilter_cpp/blob/5df1dc5063702945f6958e4bda445dd082aed366/src/xorfilter/4wise_xor_binary_fuse_filter_lowmem.h.
    ///
    /// # Arguments
    ///
    /// * `db` - A HashMap, representing a Key-Value database, containing the data to be inserted into the filter.
    /// * `mat_elem_bit_len` - The number of bits per element in the filter's matrix.
    /// * `max_attempt_count` - The maximum number of attempts to construct the filter before giving up.
    ///
    /// # Returns
    ///
    /// A Result containing the constructed BinaryFuseFilter, the reverse order of the inserted data, the reverse hash values, and a mapping from hash values to keys.
    /// Returns an error if the filter could not be constructed within the given number of attempts or the key-value database is empty.
    pub fn construct_4_wise_xor_filter<'a>(
        db: &HashMap<&'a [u8], &[u8]>,
        mat_elem_bit_len: usize,
        max_attempt_count: usize,
    ) -> Result<BinaryFuseFilterIntermediateStageResult<'a>, ChalametPIRError> {
        const ARITY: u32 = 4;

        let db_size = db.len();
        if branch_opt_util::unlikely(db_size == 0) {
            return Err(ChalametPIRError::EmptyKVDatabase);
        }

        let segment_length = segment_length::<ARITY>(db_size as u32).min(1u32 << 18);

        let size_factor = size_factor::<ARITY>(db_size as u32);
        let capacity = if db_size > 1 { ((db_size as f64) * size_factor).round() as u32 } else { 0 };

        let init_segment_count = capacity.div_ceil(segment_length);
        let (num_fingerprints, segment_count) = {
            let array_len = init_segment_count * segment_length;
            let segment_count: u32 = {
                let proposed = array_len.div_ceil(segment_length);
                if proposed < ARITY { 1 } else { proposed - (ARITY - 1) }
            };
            let array_len: u32 = (segment_count + ARITY - 1) * segment_length;
            (array_len as usize, segment_count)
        };
        let segment_count_length = segment_count * segment_length;

        let mut alone = vec![0u32; num_fingerprints];
        let mut t2count = vec![0u8; num_fingerprints];
        let mut t2hash = vec![0u64; num_fingerprints];
        let mut reverse_h = vec![0u8; db_size];
        let mut reverse_order = vec![0u64; db_size + 1];
        reverse_order[db_size] = 1;

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

        let mut h0123 = [0u32; 7];

        let mut done = false;
        let mut ultimate_size = 0;

        let mut seed = [0u8; 32];

        #[cfg(feature = "wasm")]
        let mut rng = StdRand::default();
        #[cfg(not(feature = "wasm"))]
        let mut rng = ChaCha20Rng::from_os_rng();

        for _ in 0..max_attempt_count {
            #[cfg(not(feature = "wasm"))]
            rng.fill_bytes(&mut seed);
            #[cfg(feature = "wasm")]
            seed.fill_with(|| rng.next_u32() as u8);

            for (idx, val) in start_pos.iter_mut().enumerate().take(start_pos_len) {
                *val = (((idx as u64) * (db_size as u64)) >> block_bits) as usize;
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

            let mut count_mask = 0u8;
            for &hash in reverse_order.iter().take(db_size) {
                let (h0, h1, h2, h3) = hash_batch_for_4_wise_xor_filter(hash, segment_length, segment_count_length);
                let (h0, h1, h2, h3) = (h0 as usize, h1 as usize, h2 as usize, h3 as usize);

                t2count[h0] += 4;
                t2hash[h0] ^= hash;
                count_mask |= t2count[h0];

                t2count[h1] += 4;
                t2count[h1] ^= 1u8;
                t2hash[h1] ^= hash;
                count_mask |= t2count[h1];

                t2count[h2] += 4;
                t2count[h2] ^= 2u8;
                t2hash[h2] ^= hash;
                count_mask |= t2count[h2];

                t2count[h3] += 4;
                t2count[h3] ^= 3u8;
                t2hash[h3] ^= hash;
                count_mask |= t2count[h3];
            }

            if count_mask >= 0x80 {
                reverse_order[..db_size].fill(0);
                t2count.fill(0);
                t2hash.fill(0);

                continue;
            }

            let mut qsize = 0;
            for (idx, &count) in t2count.iter().enumerate().take(num_fingerprints) {
                alone[qsize] = idx as u32;
                if (count >> 2) == 1 {
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

                    let (h0, h1, h2, h3) = hash_batch_for_4_wise_xor_filter(hash, segment_length, segment_count_length);

                    h0123[1] = h1;
                    h0123[2] = h2;
                    h0123[3] = h3;
                    h0123[4] = h0;
                    h0123[5] = h0123[1];
                    h0123[6] = h0123[2];

                    let other_index: usize = h0123[(found + 1) as usize] as usize;
                    alone[qsize] = other_index as u32;
                    qsize += if (t2count[other_index] >> 2) == 2 { 1 } else { 0 };

                    t2count[other_index] -= 4;
                    t2count[other_index] ^= mod4(found + 1);
                    t2hash[other_index] ^= hash;

                    let other_index = h0123[(found + 2) as usize] as usize;
                    alone[qsize] = other_index as u32;
                    qsize += if (t2count[other_index] >> 2) == 2 { 1 } else { 0 };

                    t2count[other_index] -= 4;
                    t2count[other_index] ^= mod4(found + 2);
                    t2hash[other_index] ^= hash;

                    let other_index = h0123[(found + 3) as usize] as usize;
                    alone[qsize] = other_index as u32;
                    qsize += if (t2count[other_index] >> 2) == 2 { 1 } else { 0 };

                    t2count[other_index] -= 4;
                    t2count[other_index] ^= mod4(found + 3);
                    t2hash[other_index] ^= hash;
                }
            }

            if stack_size == db_size {
                ultimate_size = stack_size;
                done = true;

                break;
            }

            reverse_order[..db_size].fill(0);
            t2count.fill(0);
            t2hash.fill(0);
        }

        if branch_opt_util::unlikely(!done) {
            return Err(ChalametPIRError::ExhaustedAllAttemptsToBuild4WiseXorFilter(max_attempt_count));
        }

        Ok((
            BinaryFuseFilter {
                seed,
                arity: ARITY,
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

    pub fn bits_per_entry(&self) -> f64 {
        ((self.num_fingerprints as f64) * (self.mat_elem_bit_len as f64)) / (self.filter_size as f64)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let offset0 = 0;
        let offset1 = offset0 + self.seed.len();
        let offset2 = offset1 + std::mem::size_of_val(&self.arity);
        let offset3 = offset2 + std::mem::size_of_val(&self.segment_length);
        let offset4 = offset3 + std::mem::size_of_val(&self.segment_count_length);
        let offset5 = offset4 + std::mem::size_of_val(&self.num_fingerprints);
        let offset6 = offset5 + std::mem::size_of_val(&self.filter_size);
        let total_byte_len = offset6 + std::mem::size_of_val(&self.mat_elem_bit_len);

        let mut bytes = vec![0u8; total_byte_len];

        unsafe {
            bytes.get_unchecked_mut(offset0..offset1).copy_from_slice(&self.seed);
            bytes.get_unchecked_mut(offset1..offset2).copy_from_slice(&self.arity.to_le_bytes());
            bytes.get_unchecked_mut(offset2..offset3).copy_from_slice(&self.segment_length.to_le_bytes());
            #[rustfmt::skip]
            bytes.get_unchecked_mut(offset3..offset4).copy_from_slice(&self.segment_count_length.to_le_bytes());
            bytes.get_unchecked_mut(offset4..offset5).copy_from_slice(&self.num_fingerprints.to_le_bytes());
            bytes.get_unchecked_mut(offset5..offset6).copy_from_slice(&self.filter_size.to_le_bytes());
            bytes.get_unchecked_mut(offset6..).copy_from_slice(&self.mat_elem_bit_len.to_le_bytes());
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BinaryFuseFilter, ChalametPIRError> {
        const OFFSET0: usize = 0;
        const OFFSET1: usize = OFFSET0 + std::mem::size_of::<[u8; 32]>();
        const OFFSET2: usize = OFFSET1 + std::mem::size_of::<u32>();
        const OFFSET3: usize = OFFSET2 + std::mem::size_of::<u32>();
        const OFFSET4: usize = OFFSET3 + std::mem::size_of::<u32>();
        const OFFSET5: usize = OFFSET4 + std::mem::size_of::<usize>();
        const OFFSET6: usize = OFFSET5 + std::mem::size_of::<usize>();
        const EXPECTED_BYTE_LEN: usize = OFFSET6 + std::mem::size_of::<usize>();

        if branch_opt_util::unlikely(EXPECTED_BYTE_LEN != bytes.len()) {
            return Err(ChalametPIRError::FailedToDeserializeFilterFromBytes);
        }

        Ok(unsafe {
            BinaryFuseFilter {
                seed: bytes.get_unchecked(OFFSET0..OFFSET1).try_into().unwrap(),
                arity: u32::from_le_bytes(bytes.get_unchecked(OFFSET1..OFFSET2).try_into().unwrap()),
                segment_length: u32::from_le_bytes(bytes.get_unchecked(OFFSET2..OFFSET3).try_into().unwrap()),
                segment_count_length: u32::from_le_bytes(bytes.get_unchecked(OFFSET3..OFFSET4).try_into().unwrap()),
                num_fingerprints: usize::from_le_bytes(bytes.get_unchecked(OFFSET4..OFFSET5).try_into().unwrap()),
                filter_size: usize::from_le_bytes(bytes.get_unchecked(OFFSET5..OFFSET6).try_into().unwrap()),
                mat_elem_bit_len: usize::from_le_bytes(bytes.get_unchecked(OFFSET6..).try_into().unwrap()),
            }
        })
    }
}

// Various utility functions, used in the construction of Binary Fuse Filters.

#[inline(always)]
pub fn segment_length<const ARITY: u32>(size: u32) -> u32 {
    if size == 0 {
        return 4;
    }

    match ARITY {
        3 => 1u32 << ((size as f64).ln() / 3.33_f64.ln() + 2.25).floor() as usize,
        4 => 1u32 << ((size as f64).ln() / 2.91_f64.ln() - 0.5).floor() as usize,
        _ => 65536,
    }
}

#[inline(always)]
pub fn size_factor<const ARITY: u32>(size: u32) -> f64 {
    match ARITY {
        3 => 1.125_f64.max(0.875 + 0.25 * 1e6_f64.ln() / (size as f64).ln()),
        4 => 1.075_f64.max(0.77 + 0.305 * 6e5_f64.ln() / (size as f64).ln()),
        _ => 2.0,
    }
}

#[inline(always)]
pub const fn mod3(x: u8) -> u8 {
    if x > 2 { x - 3 } else { x }
}

#[inline(always)]
pub const fn mod4(x: u8) -> u8 {
    if x > 3 { x - 4 } else { x }
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
    murmur64(key.wrapping_add(seed))
}

#[inline(always)]
pub fn hash_of_key(key: &[u8]) -> [u64; 4] {
    let mut hasher = TurboShake128::default();
    hasher.absorb(key);
    hasher.finalize::<{ TurboShake128::DEFAULT_DOMAIN_SEPARATOR }>();

    let mut digest_bytes = [0u8; params::HASHED_KEY_BYTE_LEN];
    hasher.squeeze(&mut digest_bytes);

    unsafe {
        [
            u64::from_le_bytes(digest_bytes[..8].try_into().unwrap_unchecked()),
            u64::from_le_bytes(digest_bytes[8..16].try_into().unwrap_unchecked()),
            u64::from_le_bytes(digest_bytes[16..24].try_into().unwrap_unchecked()),
            u64::from_le_bytes(digest_bytes[24..].try_into().unwrap_unchecked()),
        ]
    }
}

/// Collects inspiration from https://github.com/claucece/chalamet/blob/515ff1479940a2917ad247acb6ab9e6d27e139a1/bff-modp/src/prelude/mod.rs#L43-L62.
#[inline(always)]
pub fn mix256(key: &[u64; 4], seed: &[u8; 32]) -> u64 {
    let seed_words = unsafe {
        [
            u64::from_le_bytes(seed[..8].try_into().unwrap_unchecked()),
            u64::from_le_bytes(seed[8..16].try_into().unwrap_unchecked()),
            u64::from_le_bytes(seed[16..24].try_into().unwrap_unchecked()),
            u64::from_le_bytes(seed[24..].try_into().unwrap_unchecked()),
        ]
    };

    key.iter()
        .map(|&k| seed_words.into_iter().fold(0u64, |acc, seed_word| murmur64(acc.wrapping_add(mix(k, seed_word)))))
        .fold(0, |acc, r| acc.overflowing_add(r).0)
}

/// Collects inspiration from https://github.com/FastFilter/xor_singleheader/blob/a5a3630619f375a5610938bdfd61ec7e9f9fed1c/include/binaryfusefilter.h#L154-L164.
#[inline(always)]
pub const fn hash_batch_for_3_wise_xor_filter(hash: u64, segment_length: u32, segment_count_length: u32) -> (u32, u32, u32) {
    let segment_length_mask = segment_length - 1;
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;

    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;

    h1 ^= ((hash >> 18) as u32) & segment_length_mask;
    h2 ^= (hash as u32) & segment_length_mask;

    (h0, h1, h2)
}

/// Collects inspiration from https://github.com/FastFilter/fastfilter_cpp/blob/5df1dc5063702945f6958e4bda445dd082aed366/src/xorfilter/4wise_xor_binary_fuse_filter_lowmem.h#L57-L67.
#[inline(always)]
pub const fn hash_batch_for_4_wise_xor_filter(hash: u64, segment_length: u32, segment_count_length: u32) -> (u32, u32, u32, u32) {
    let segment_length_mask = segment_length - 1;
    let hi = ((hash as u128 * segment_count_length as u128) >> 64) as u64;

    let h0 = hi as u32;
    let mut h1 = h0 + segment_length;
    let mut h2 = h1 + segment_length;
    let mut h3 = h2 + segment_length;

    h1 ^= (hash as u32) & segment_length_mask;
    h2 ^= ((hash >> 16) as u32) & segment_length_mask;
    h3 ^= ((hash >> 32) as u32) & segment_length_mask;

    (h0, h1, h2, h3)
}
