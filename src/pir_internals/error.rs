use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum ChalametPIRError {
    // Matrix
    InvalidMatrixDimension,
    IncompatibleDimensionForMatrixMultiplication,
    IncompatibleDimensionForMatrixAddition,
    InvalidNumberOfElementsInMatrix,
    IncompatibleDimensionForRowVectorTransposedMatrixMultiplication,
    InvalidDimensionForVector,

    // Binary Fuse Fiter
    EmptyKVDatabase,
    ExhaustedAllAttemptsToBuild3WiseXorFilter(usize),
    ExhaustedAllAttemptsToBuild4WiseXorFilter(usize),
    KeyNotFoundInMap,
    RowNotDecodable,
    DecodedRowNotPrependedWithDigestOfKey,
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
        }
    }
}

impl Error for ChalametPIRError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
