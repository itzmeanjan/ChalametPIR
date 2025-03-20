#version 460
#pragma shader_stage(compute)

layout(local_size_x = 8, local_size_y = 8, local_size_z = 1) in;

layout(set = 0, binding = 0) buffer readonly MatrixA {
  uint rows;
  uint cols;
  uint[] elems;
}
matrix_a;

layout(set = 0, binding = 1) buffer writeonly MatrixB {
  uint rows;
  uint cols;
  uint[] elems;
}
matrix_b;

void main() {
  const uint row_idx = gl_GlobalInvocationID.x;
  const uint col_idx = gl_GlobalInvocationID.y;

  if (row_idx >= matrix_a.cols || col_idx >= matrix_a.rows) {
    return;
  }

  if ((row_idx == 0) && (col_idx == 0)) {
    matrix_b.rows = matrix_a.cols;
    matrix_b.cols = matrix_a.rows;
  }

  matrix_b.elems[row_idx * matrix_a.rows + col_idx] =
      matrix_a.elems[row_idx * matrix_a.cols + col_idx];
}
