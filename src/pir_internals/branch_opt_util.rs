/// See https://users.rust-lang.org/t/compiler-hint-for-unlikely-likely-for-if-branches/62102/4

#[inline]
#[cold]
pub fn cold() {}

#[inline]
pub fn likely(b: bool) -> bool {
    if !b {
        cold()
    }
    b
}

#[inline]
pub fn unlikely(b: bool) -> bool {
    if b {
        cold()
    }
    b
}
