#version 460
#pragma shader_stage(compute)

layout(local_size_x = 8, local_size_y = 8, local_size_z = 1) in;

layout(set = 0, binding = 0) buffer readonly MatrixA {
  uint rows;
  uint cols;
  uint[] elems;
}
lhs_vec;

layout(set = 0, binding = 1) buffer readonly MatrixB {
  uint rows;
  uint cols;
  uint[] elems;
}
rhs_trans_mat;

layout(set = 0, binding = 2) buffer writeonly MatrixC {
  uint rows;
  uint cols;
  uint[] elems;
}
res_vec;

void main() {
  const uint row_idx = gl_GlobalInvocationID.x;
  const uint col_idx = gl_GlobalInvocationID.y;
  const uint res_vec_num_cols_sqrt = uint(sqrt(rhs_trans_mat.rows)) + 1;
  const uint lin_idx = row_idx * res_vec_num_cols_sqrt + col_idx;

  if (lin_idx >= rhs_trans_mat.rows) {
    return;
  }

  if ((row_idx == 0) && (col_idx == 0)) {
    res_vec.rows = lhs_vec.rows;
    res_vec.cols = rhs_trans_mat.rows;
  }

  uint sum = 0;
  for (uint i = 0; i < lhs_vec.cols; i++) {
    sum += lhs_vec.elems[i] *
           rhs_trans_mat.elems[lin_idx * rhs_trans_mat.cols + i];
  }

  res_vec.elems[lin_idx] = sum;
}
