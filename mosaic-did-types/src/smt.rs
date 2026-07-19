//! Sparse Merkle Trie for batch-anchoring off-chain proofs (§6.4).
//!
//! Fixed height 10 (1024 leaves) using `json_digest` for BLAKE3 hashing.
//! An `InclusionProof` proves a leaf exists at a specific index without
//! revealing the other leaves.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Height of the Sparse Merkle Trie (10 → 1024 leaves).
pub const HEIGHT: usize = 10;
/// Number of leaf positions.
pub const LEAF_COUNT: usize = 1 << HEIGHT;

/// A hash value — a `json_digest` string (BLAKE3, `cm` prefix).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Hash(pub String);

impl Hash {
    /// Create a hash from a `json_digest` string.
    pub fn from_digest(digest: String) -> Self {
        Hash(digest)
    }

    /// The empty-leaf hash — digest of `{}`.
    pub fn empty_leaf() -> Hash {
        let digest = json_digest::digest_data_blake3(&serde_json::json!({}))
            .expect("digest_data on empty object should never fail");
        Hash(digest)
    }

    /// Get the underlying digest string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Merge two child hashes into a parent hash.
    ///
    /// Parent = `digest_data_blake3({"left": left.0, "right": right.0})`.
    pub fn merge(left: &Hash, right: &Hash) -> Self {
        let node = serde_json::json!({ "left": left.0, "right": right.0 });
        let digest = json_digest::digest_data_blake3(&node)
            .expect("digest_data on two-field object should never fail");
        Hash(digest)
    }
}

// ===== Inclusion Proof =====

/// A self-contained, serializable Merkle inclusion proof.
///
/// Can be handed out by the batch service to individual document owners.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InclusionProof {
    /// The leaf index (0..1023).
    pub leaf_index: usize,
    /// The hash of the leaf data.
    pub leaf_hash: Hash,
    /// Sibling hashes along the path (one per level, leaf→root).
    pub sibling_hashes: [Hash; HEIGHT],
}

impl InclusionProof {
    /// Compute the root hash by walking up the proof path.
    pub fn compute_root(&self) -> Hash {
        let mut current = self.leaf_hash.clone();
        let mut index = self.leaf_index;

        for sibling in self.sibling_hashes.iter() {
            if index & 1 == 0 {
                current = Hash::merge(&current, sibling);
            } else {
                current = Hash::merge(sibling, &current);
            }
            index >>= 1;
        }

        current
    }

    /// Verify this proof against an expected root hash.
    pub fn verify(&self, expected_root: &Hash) -> bool {
        &self.compute_root() == expected_root
    }
}

// ===== Sparse Merkle Trie =====

/// Sparse Merkle Trie with 2^HEIGHT leaf slots.
/// Only non-default nodes are stored.
pub struct SparseMerkleTrie {
    /// Maps (level, index_in_level) → hash. Level 0 = leaves.
    nodes: BTreeMap<(usize, usize), Hash>,
    /// Precomputed default hashes for each level.
    default_hashes: [Hash; HEIGHT + 1],
}

impl SparseMerkleTrie {
    fn build_default_hashes() -> [Hash; HEIGHT + 1] {
        let empty = Hash::empty_leaf();
        let mut defaults: [Hash; HEIGHT + 1] = core::array::from_fn(|_| empty.clone());
        for level in 1..=HEIGHT {
            defaults[level] = Hash::merge(&defaults[level - 1], &defaults[level - 1]);
        }
        defaults
    }

    /// Create an empty SMT.
    pub fn new() -> Self {
        Self { nodes: BTreeMap::new(), default_hashes: Self::build_default_hashes() }
    }

    /// Insert a leaf hash at `leaf_index`. Updates all ancestors.
    pub fn insert(&mut self, leaf_index: usize, hash: Hash) {
        assert!(leaf_index < LEAF_COUNT, "leaf index {leaf_index} >= {LEAF_COUNT}");

        let mut level = 0;
        let mut pos = leaf_index;
        self.nodes.insert((level, pos), hash.clone());

        while level < HEIGHT {
            let parent_pos = pos / 2;
            let left_pos = parent_pos * 2;
            let right_pos = left_pos + 1;

            let left = self.nodes.get(&(level, left_pos)).unwrap_or(&self.default_hashes[level]);
            let right = self.nodes.get(&(level, right_pos)).unwrap_or(&self.default_hashes[level]);

            let parent_hash = Hash::merge(left, right);
            level += 1;
            pos = parent_pos;

            if parent_hash != self.default_hashes[level] {
                self.nodes.insert((level, pos), parent_hash);
            } else {
                self.nodes.remove(&(level, pos));
            }
        }
    }

    /// Get the current root hash.
    pub fn root(&self) -> &Hash {
        self.nodes.get(&(HEIGHT, 0)).unwrap_or(&self.default_hashes[HEIGHT])
    }

    /// Generate an inclusion proof for `leaf_index`. Returns `None` if the leaf
    /// was never inserted.
    pub fn inclusion_proof(&self, leaf_index: usize) -> Option<InclusionProof> {
        assert!(leaf_index < LEAF_COUNT, "leaf index {leaf_index} >= {LEAF_COUNT}");

        let leaf_hash = self.nodes.get(&(0, leaf_index))?.clone();
        let mut siblings = Vec::with_capacity(HEIGHT);
        let mut index = leaf_index;

        for level in 0..HEIGHT {
            let sibling_pos = if index & 1 == 0 { index + 1 } else { index - 1 };
            let sibling = self
                .nodes
                .get(&(level, sibling_pos))
                .unwrap_or(&self.default_hashes[level])
                .clone();
            siblings.push(sibling);
            index /= 2;
        }

        Some(InclusionProof {
            leaf_index,
            leaf_hash,
            sibling_hashes: siblings.try_into().expect("HEIGHT siblings collected"),
        })
    }
}

impl Default for SparseMerkleTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_leaf_is_stable() {
        let a = Hash::empty_leaf();
        let b = Hash::empty_leaf();
        assert_eq!(a, b);
        assert!(!a.as_str().is_empty());
    }

    #[test]
    fn merge_two_empty_leaves_equals_level_1_default() {
        let left = Hash::empty_leaf();
        let right = Hash::empty_leaf();
        let parent = Hash::merge(&left, &right);
        let trie = SparseMerkleTrie::new();
        assert_eq!(parent, trie.default_hashes[1]);
    }

    #[test]
    fn single_leaf_proof() {
        let mut trie = SparseMerkleTrie::new();
        let record = serde_json::json!({"payload": "invoice #42"});
        let leaf_hash = Hash::from_digest(json_digest::digest_data_blake3(&record).unwrap());
        trie.insert(0, leaf_hash.clone());

        let proof = trie.inclusion_proof(0).expect("leaf should exist");
        assert!(proof.verify(trie.root()));
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.leaf_hash, leaf_hash);
    }

    #[test]
    fn multiple_leaves_independent_proofs() {
        let mut trie = SparseMerkleTrie::new();
        for i in [0, 100, 512, 1023] {
            let record = serde_json::json!({"idx": i});
            let hash = Hash::from_digest(json_digest::digest_data_blake3(&record).unwrap());
            trie.insert(i, hash);
        }

        for i in [0, 100, 512, 1023] {
            let proof = trie.inclusion_proof(i).expect("proof should exist");
            assert!(proof.verify(trie.root()), "proof for index {i} failed");
        }
    }

    #[test]
    fn uninserted_leaf_returns_none() {
        let trie = SparseMerkleTrie::new();
        assert!(trie.inclusion_proof(0).is_none());
    }

    #[test]
    fn proof_against_wrong_root_fails() {
        let mut trie = SparseMerkleTrie::new();
        let record = serde_json::json!({"data": "test"});
        let hash = Hash::from_digest(json_digest::digest_data_blake3(&record).unwrap());
        trie.insert(42, hash);

        let proof = trie.inclusion_proof(42).unwrap();
        let wrong_root = Hash::empty_leaf();
        assert!(!proof.verify(&wrong_root));
    }
}
