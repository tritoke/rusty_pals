use std::collections::HashSet;
use std::hash::Hash;

/// Detect whether an iterator contains a duplicate element
pub fn has_duplicate<T>(it: impl IntoIterator<Item = T>) -> bool
where
    T: Eq + Hash,
{
    let mut set = HashSet::new();
    for i in it {
        if !set.insert(i) {
            return true;
        }
    }

    false
}
