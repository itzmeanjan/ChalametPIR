pub const LWE_DIMENSION: u32 = 1774;

pub const BIT_SECURITY_LEVEL: usize = 128;
pub const SEED_BYTE_LEN: usize = (2 * BIT_SECURITY_LEVEL) / u8::BITS as usize;
pub const HASHED_KEY_BYTE_LEN: usize = (2 * BIT_SECURITY_LEVEL) / u8::BITS as usize;

pub const SERVER_SETUP_MAX_ATTEMPT_COUNT: usize = 100;
