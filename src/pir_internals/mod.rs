pub mod binary_fuse_filter;
pub mod branch_opt_util;
pub mod error;
pub mod matrix;
pub mod params;
pub mod serialization;

#[cfg(feature = "gpu")]
pub mod gpu;
#[cfg(feature = "gpu")]
pub mod mat_x_mat_shader;
#[cfg(feature = "gpu")]
pub mod mat_transpose_shader;
