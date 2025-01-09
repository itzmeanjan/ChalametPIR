pub struct Matrix {
    rows: usize,
    cols: usize,
    elems: Vec<u32>,
}

impl Matrix {
    pub fn new(rows: usize, cols: usize) -> Option<Matrix> {
        if !((rows > 0) && (cols > 0)) {
            None
        } else {
            Some(Matrix {
                rows,
                cols,
                elems: vec![0; rows * cols],
            })
        }
    }
}
