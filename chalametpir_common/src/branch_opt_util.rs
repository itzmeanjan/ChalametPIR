/// Rust equivalent for C++'s compiler hint on which branch is more/ less likely https://en.cppreference.com/w/cpp/language/attributes/likely.
/// Collects inspiration from https://users.rust-lang.org/t/compiler-hint-for-unlikely-likely-for-if-branches/62102/4.

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
