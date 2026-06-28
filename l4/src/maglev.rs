//! Maglev consistent-hashing table construction.
//!
//! Each backend gets a pseudo-random permutation of the `M` table slots derived
//! from two hashes of its key. We then fill the table round-robin so that every
//! slot ends up owned by a backend with near-perfect, minimally-disruptive
//! distribution when the backend set changes.

use l4_common::M;
use xxhash_rust::xxh3::xxh3_64_with_seed;

const SEED_OFFSET: u64 = 0xDEAD_BEEF;
const SEED_SKIP: u64 = 0xCAFE_BABE;

/// `(offset, skip)` defining a backend's permutation: `perm(k) = (offset + k*skip) % M`.
fn permutation_params(key: &str) -> (usize, usize) {
    let m = M as usize;
    let offset = (xxh3_64_with_seed(key.as_bytes(), SEED_OFFSET) as usize) % m;
    let skip = (xxh3_64_with_seed(key.as_bytes(), SEED_SKIP) as usize) % (m - 1) + 1;
    (offset, skip)
}

/// Build the lookup table for the given backend keys.
///
/// Returns a vector of length `M` mapping each slot to the *local* index of the
/// owning backend (`0..keys.len()`). Empty slots (only possible when there are
/// no backends) are marked with `u32::MAX`.
pub fn build_table(keys: &[String]) -> Vec<u32> {
    let m = M as usize;
    let mut entry = vec![u32::MAX; m];
    let n = keys.len();
    if n == 0 {
        return entry;
    }

    let params: Vec<(usize, usize)> = keys.iter().map(|k| permutation_params(k)).collect();
    let mut next = vec![0usize; n];
    let mut filled = 0usize;

    while filled < m {
        for (j, &(offset, skip)) in params.iter().enumerate() {
            let mut c = (offset + next[j] * skip) % m;
            while entry[c] != u32::MAX {
                next[j] += 1;
                c = (offset + next[j] * skip) % m;
            }
            entry[c] = j as u32;
            next[j] += 1;
            filled += 1;
            if filled == m {
                break;
            }
        }
    }

    entry
}
