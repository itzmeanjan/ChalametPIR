pub const LWE_DIMENSION: u32 = 1774;

/// ChalametPIR's paramater choice provides 128 -bit security.
pub const BIT_SECURITY_LEVEL: usize = 128;
pub const SEED_BYTE_LEN: usize = (2 * BIT_SECURITY_LEVEL) / u8::BITS as usize;
pub const HASHED_KEY_BYTE_LEN: usize = (2 * BIT_SECURITY_LEVEL) / u8::BITS as usize;

/// Maximum number of times PIR server attempts to encode key-value database,
/// using Binary Fuse Filter, before giving up.
pub const SERVER_SETUP_MAX_ATTEMPT_COUNT: usize = 100;

/// For key-value database with maximum number of entries 2^42,
/// computed using https://play.rust-lang.org/?version=stable&mode=debug&edition=2024&gist=dff0acb4b039694b899b48409df01f2c.
pub const MIN_CIPHER_TEXT_BIT_LEN: usize = 4;
/// For key-value database with single entry, which is minimum required number of entries,
/// computed using https://play.rust-lang.org/?version=stable&mode=debug&edition=2024&gist=dff0acb4b039694b899b48409df01f2c.
pub const MAX_CIPHER_TEXT_BIT_LEN: usize = 14;
