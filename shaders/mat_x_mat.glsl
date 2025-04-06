#version 460
#pragma shader_stage(compute)

layout(local_size_x = 8, local_size_y = 8, local_size_z = 1) in;

layout(set = 0, binding = 0) buffer readonly MatrixA {
  uint rows;
  uint cols;
  uint[] elems;
}
matrix_a;

layout(set = 0, binding = 1) buffer readonly MatrixB {
  uint rows;
  uint cols;
  uint[] elems;
}
matrix_b;

layout(set = 0, binding = 2) buffer writeonly MatrixC {
  uint rows;
  uint cols;
  uint[] elems;
}
matrix_c;

void main() {
  const uint row_idx = gl_GlobalInvocationID.x;
  const uint col_idx = gl_GlobalInvocationID.y;

  if (row_idx >= matrix_a.rows || col_idx >= matrix_b.cols) {
    return;
  }

  if ((row_idx == 0) && (col_idx == 0)) {
    matrix_c.rows = matrix_a.rows;
    matrix_c.cols = matrix_b.cols;
  }

  uint sum = 0;
  for (uint i = 0; i < matrix_a.cols; i++) {
    sum += matrix_a.elems[row_idx * matrix_a.cols + i] *
           matrix_b.elems[i * matrix_b.cols + col_idx];
  }

  matrix_c.elems[row_idx * matrix_b.cols + col_idx] = sum;
}
