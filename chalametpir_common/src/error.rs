use std::{error::Error, fmt::Display};

/// ChalametPIR error codes.
///
/// This enum represents all the possible errors that can occur during the execution of the ChalametPIR protocol.
/// It includes errors related to matrix operations, binary fuse filter operations, and PIR operations.
#[derive(Debug, PartialEq)]
pub enum ChalametPIRError {
    // GPU
    VulkanLibraryNotFound,
    VulkanInstanceCreationFailed,
    VulkanPhysicalDeviceNotFound,
    VulkanDeviceCreationFailed,
    VulkanBufferCreationFailed,
    VulkanCommandBufferBuilderCreationFailed,
    VulkanCommandBufferRecordingFailed,
    VulkanCommandBufferBuildingFailed,
    VulkanCommandBufferExecutionFailed,
    VulkanReadingFromBufferFailed,
    VulkanComputeShaderLoadingFailed,
    VulkanComputePipelineCreationFailed,
    VulkanDescriptorSetCreationFailed,

    // Matrix
    InvalidMatrixDimension,
    IncompatibleDimensionForMatrixMultiplication,
    IncompatibleDimensionForMatrixAddition,
    InvalidNumberOfElementsInMatrix,
    IncompatibleDimensionForRowVectorTransposedMatrixMultiplication,
    InvalidDimensionForVector,
    FailedToDeserializeMatrixFromBytes,

    // Binary Fuse Filter
    EmptyKVDatabase,
    ExhaustedAllAttemptsToBuild3WiseXorFilter(usize),
    ExhaustedAllAttemptsToBuild4WiseXorFilter(usize),
    RowNotDecodable,
    DecodedRowNotPrependedWithDigestOfKey,
    FailedToDeserializeFilterFromBytes,

    // PIR
    KVDatabaseSizeTooLarge,
    InvalidHintMatrix,
    PendingQueryExistsForKey,
    PendingQueryDoesNotExistForKey,
    ArithmeticOverflowAddingQueryIndicator,
    UnsupportedArityForBinaryFuseFilter,
    InvalidResponseVector,
    ImpossibleEncodedDBMatrixElementBitLength,
}

impl Display for ChalametPIRError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VulkanLibraryNotFound => write!(f, "Failed to load the default Vulkan library for the system."),
            Self::VulkanInstanceCreationFailed => write!(f, "Failed to create a new instance of Vulkan."),
            Self::VulkanPhysicalDeviceNotFound => write!(f, "Failed to find a compatible Vulkan physical device."),
            Self::VulkanDeviceCreationFailed => write!(f, "Failed to create a Vulkan device and associated queue."),
            Self::VulkanBufferCreationFailed => write!(f, "Failed to create a Vulkan transfer source buffer."),
            Self::VulkanCommandBufferBuilderCreationFailed => write!(f, "Failed to create a Vulkan command buffer builder."),
            Self::VulkanCommandBufferRecordingFailed => write!(f, "Failed to record command in a Vulkan command buffer."),
            Self::VulkanCommandBufferBuildingFailed => write!(f, "Failed to build a Vulkan command buffer."),
            Self::VulkanCommandBufferExecutionFailed => write!(f, "Failed to execute the Vulkan command buffer."),
            Self::VulkanReadingFromBufferFailed => write!(f, "Failed to read from Vulkan buuffer."),
            Self::VulkanComputeShaderLoadingFailed => write!(f, "Failed to load Vulkan compute shader module."),
            Self::VulkanComputePipelineCreationFailed => write!(f, "Failed to create Vulkan compute pipeline."),
            Self::VulkanDescriptorSetCreationFailed => write!(f, "Failed to create descriptor set for Vulkan compute pipeline."),

            Self::InvalidMatrixDimension => write!(f, "The number of rows and columns in the matrix must be non-zero."),
            Self::IncompatibleDimensionForMatrixMultiplication => write!(f, "The matrix dimensions do not allow multiplication."),
            Self::IncompatibleDimensionForMatrixAddition => write!(f, "The matrix dimensions do not allow addition."),
            Self::InvalidNumberOfElementsInMatrix => write!(f, "The matrix must have \"rows * columns\" elements."),
            Self::IncompatibleDimensionForRowVectorTransposedMatrixMultiplication => {
                write!(f, "The dimensions are incompatible for multiplication of a row vector and a transposed matrix.")
            }
            Self::InvalidDimensionForVector => write!(f, "A vector must have either one row or one column."),
            Self::FailedToDeserializeMatrixFromBytes => write!(f, "Matrix deserialization failed"),

            Self::EmptyKVDatabase => write!(f, "Cannot encode empty key-value database."),
            Self::ExhaustedAllAttemptsToBuild3WiseXorFilter(max_num_attempts) => {
                write!(f, "Exhausted {} attempts to build 3-wise XOR binary fuse filter.", max_num_attempts)
            }
            Self::ExhaustedAllAttemptsToBuild4WiseXorFilter(max_num_attempts) => {
                write!(f, "Exhausted {} attempts to build 4-wise XOR binary fuse filter.", max_num_attempts)
            }
            Self::RowNotDecodable => write!(f, "Encoded KV database matrix's row cannot be decoded."),
            Self::DecodedRowNotPrependedWithDigestOfKey => write!(f, "Decoded row does not have the digest of the key prepended to it."),
            Self::FailedToDeserializeFilterFromBytes => write!(f, "Binary fuse filter deserialization failed"),

            Self::KVDatabaseSizeTooLarge => write!(f, "The key-value database is too large; it can have a maximum of 2^42 entries."),
            Self::InvalidHintMatrix => write!(f, "Unexpected number of rows in the hint matrix."),
            Self::PendingQueryExistsForKey => write!(f, "A pending query for this key was found in the internal client state."),
            Self::PendingQueryDoesNotExistForKey => write!(f, "No pending query for this key exists in the internal client state."),
            Self::ArithmeticOverflowAddingQueryIndicator => {
                write!(f, "Encountered arithmetic overflow while adding the query indicator to the query vector 'b'.")
            }
            Self::UnsupportedArityForBinaryFuseFilter => write!(f, "Binary Fuse Filter supports arity of either 3 or 4."),
            Self::InvalidResponseVector => write!(f, "Unexpected dimension of the response vector."),
            Self::ImpossibleEncodedDBMatrixElementBitLength => write!(f, "Encoded database matrix's element bit length mustn't ever exceed 16."),
        }
    }
}

impl Error for ChalametPIRError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
