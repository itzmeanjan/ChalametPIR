use std::{error::Error, fmt::Display};

#[derive(Debug, PartialEq)]
pub enum ChalametPIRError {
    // Matrix
    InvalidMatrixDimension,
    IncompatibleDimensionForMatrixMultiplication,
    IncompatibleDimensionForMatrixAddition,
    InvalidNumberOfElementsInMatrix,
    IncompatibleDimensionForRowVectorTransposedMatrixMultiplication,
    InvalidDimensionForVector,
    FailedToSerializeMatrixToBytes(String),
    FailedToDeserializeMatrixFromBytes(String),

    // Binary Fuse Fiter
    EmptyKVDatabase,
    ExhaustedAllAttemptsToBuild3WiseXorFilter(usize),
    ExhaustedAllAttemptsToBuild4WiseXorFilter(usize),
    KeyNotFoundInMap,
    RowNotDecodable,
    DecodedRowNotPrependedWithDigestOfKey,
    FailedToSerializeFilterToBytes(String),
    FailedToDeserializeFilterFromBytes(String),

    // PIR
    KVDatabaseSizeTooLarge,
    InvalidHintMatrix,
    PendingQueryExistsForKey,
    PendingQueryDoesNotExistForKey,
    ArithmeticOverflowAddingQueryIndicator,
    UnsupportedArityForBinaryFuseFilter,
    InvalidResponseVector,
}

impl Display for ChalametPIRError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMatrixDimension => write!(f, "The number of rows and columns in the matrix must be non-zero."),
            Self::IncompatibleDimensionForMatrixMultiplication => write!(f, "The matrix dimensions do not allow multiplication."),
            Self::IncompatibleDimensionForMatrixAddition => write!(f, "The matrix dimensions do not allow addition."),
            Self::InvalidNumberOfElementsInMatrix => write!(f, "The matrix must have 'rows * columns' elements."),
            Self::IncompatibleDimensionForRowVectorTransposedMatrixMultiplication => {
                write!(f, "The dimensions are incompatible for multiplication of a row vector and a transposed matrix.")
            }
            Self::InvalidDimensionForVector => write!(f, "A vector must have either one row or one column."),
            Self::FailedToSerializeMatrixToBytes(e) => write!(f, "Matrix serialization failed with: {}", e),
            Self::FailedToDeserializeMatrixFromBytes(e) => write!(f, "Matrix deserialization failed with: {}", e),

            Self::EmptyKVDatabase => write!(f, "Can not encode empty key-value database"),
            Self::ExhaustedAllAttemptsToBuild3WiseXorFilter(max_num_attempts) => {
                write!(f, "Exhausted '{}' attempts to build 3-wise XOR binary fuse filter", max_num_attempts)
            }
            Self::ExhaustedAllAttemptsToBuild4WiseXorFilter(max_num_attempts) => {
                write!(f, "Exhausted '{}' attempts to build 4-wise XOR binary fuse filter", max_num_attempts)
            }
            Self::KeyNotFoundInMap => write!(f, "Key is not present in hashmap"),
            Self::RowNotDecodable => write!(f, "Encoded KV database matrix's row can't be decoded"),
            Self::DecodedRowNotPrependedWithDigestOfKey => write!(f, "Decoded row doesn't have digest of key prepended to it"),
            Self::FailedToSerializeFilterToBytes(e) => write!(f, "Binary fuse filter serialization failed with: {}", e),
            Self::FailedToDeserializeFilterFromBytes(e) => write!(f, "Binary fuse filter deserialization failed with: {}", e),

            Self::KVDatabaseSizeTooLarge => write!(f, "Key Value database is too large, it can have at max 2^42 entries."),
            Self::InvalidHintMatrix => write!(f, "Unexpected number of rows in hint matrix."),
            Self::PendingQueryExistsForKey => write!(f, "Pending query for this key found in internal client state."),
            Self::PendingQueryDoesNotExistForKey => write!(f, "No pending query for this key in internal client state."),
            Self::ArithmeticOverflowAddingQueryIndicator => write!(f, "Encountered arithmetic overflow while adding query indicator to the query vector 'b'."),
            Self::UnsupportedArityForBinaryFuseFilter => write!(f, "Binary Fuse Filter supports arity of either 3 or 4."),
            Self::InvalidResponseVector => write!(f, "Unexpected dimension of response vector."),
        }
    }
}

impl Error for ChalametPIRError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
