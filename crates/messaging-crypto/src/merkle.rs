// Append-only Merkle transparency log following RFC 6962 (Certificate Transparency).
//
// Hash construction:
//   leaf_hash    = SHA256(0x00 || signature || acte_uuid || timestamp || seq)
//   inner_hash   = SHA256(0x01 || left || right)
//
// The 0x00 / 0x01 domain separation prevents second-preimage attacks where a
// leaf hash could be re-interpreted as an internal node (or vice versa),
// allowing two distinct trees to share the same root.
//
// Odd subtrees are handled by RFC 6962 §2.1 splitting: at each recursion step,
// the largest power-of-two `k < n` separates left and right subtrees. Orphan
// nodes are promoted as-is rather than duplicated (the latter is the "Bitcoin"
// style which has known ambiguities — see CVE-2012-2459).

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

const LEAF_PREFIX: u8 = 0x00;
const INNER_PREFIX: u8 = 0x01;

/// Inclusion proof for a single leaf, following RFC 6962 audit path semantics.
/// `siblings` lists the audit path hashes from leaf level up to the root;
/// `leaf_index` and `tree_size` are required for the verifier to know on which
/// side each sibling sits at each recursion step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub tree_size: usize,
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Debug, Default)]
pub struct MerkleLog {
    leaves: Vec<[u8; 32]>,
}

impl MerkleLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconstruct a log from previously stored leaf hashes (e.g. loaded from DB).
    /// Does not recompute hashes — trusts the stored values.
    pub fn from_leaf_hashes(leaves: Vec<[u8; 32]>) -> Self {
        Self { leaves }
    }

    /// Append a leaf for a new message. Returns the leaf hash.
    pub fn add_leaf(
        &mut self,
        signature: &ed25519_dalek::Signature,
        acte_uuid: &uuid::Uuid,
        timestamp: i64,
        seq: u64,
    ) -> [u8; 32] {
        let leaf = leaf_hash(signature, acte_uuid, timestamp, seq);
        self.leaves.push(leaf);
        leaf
    }

    /// Compute the current Merkle root (RFC 6962 MTH). Returns None if empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.leaves.is_empty() {
            return None;
        }
        Some(mth(&self.leaves))
    }

    /// Generate a RFC 6962 audit path (PATH) for the leaf at `leaf_index`.
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }
        let mut siblings = Vec::new();
        audit_path(leaf_index, &self.leaves, &mut siblings);
        Some(MerkleProof {
            leaf_index,
            tree_size: self.leaves.len(),
            siblings,
        })
    }

    /// Verify that `leaf` is included in a tree with the given `root` using
    /// the RFC 6962 audit path verification (§2.1.1).
    pub fn verify_proof(root: &[u8; 32], leaf: &[u8; 32], proof: &MerkleProof) -> bool {
        if proof.leaf_index >= proof.tree_size {
            return false;
        }
        let computed = match recompute_root(
            *leaf,
            proof.leaf_index,
            proof.tree_size,
            &proof.siblings,
        ) {
            Some(h) => h,
            None => return false,
        };
        &computed == root
    }
}

/// Compute the leaf hash for a single message without appending to any log.
/// Includes the RFC 6962 leaf prefix (0x00) for domain separation.
pub fn leaf_hash(
    signature: &ed25519_dalek::Signature,
    acte_uuid: &uuid::Uuid,
    timestamp: i64,
    seq: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(signature.to_bytes());
    hasher.update(acte_uuid.as_bytes());
    hasher.update(timestamp.to_le_bytes());
    hasher.update(seq.to_le_bytes());
    hasher.finalize().into()
}

// ─── RFC 6962 core ────────────────────────────────────────────────────────────

/// MTH(D[n]) — Merkle Tree Hash, RFC 6962 §2.1.
/// Caller guarantees `leaves` is non-empty.
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = largest_pow2_lt(leaves.len());
    let left = mth(&leaves[..k]);
    let right = mth(&leaves[k..]);
    hash_inner(&left, &right)
}

/// PATH(m, D[n]) — RFC 6962 §2.1.1. Pushes the audit path into `out` so that
/// `out[0]` is the sibling at the leaf level and the last element is at the
/// root level. Recursion mirrors the verifier's `recompute_root`.
fn audit_path(m: usize, leaves: &[[u8; 32]], out: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if n == 1 {
        return;
    }
    let k = largest_pow2_lt(n);
    if m < k {
        audit_path(m, &leaves[..k], out);
        out.push(mth(&leaves[k..]));
    } else {
        audit_path(m - k, &leaves[k..], out);
        out.push(mth(&leaves[..k]));
    }
}

/// Inverse of `audit_path`: rebuild the root from leaf + audit path.
/// Returns None if the proof has the wrong length or shape.
fn recompute_root(
    leaf: [u8; 32],
    m: usize,
    n: usize,
    siblings: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if n == 1 {
        return if siblings.is_empty() { Some(leaf) } else { None };
    }
    if siblings.is_empty() {
        return None;
    }
    let k = largest_pow2_lt(n);
    let last = siblings.len() - 1;
    let inner = &siblings[..last];
    let top_sibling = siblings[last];
    if m < k {
        let sub = recompute_root(leaf, m, k, inner)?;
        Some(hash_inner(&sub, &top_sibling))
    } else {
        let sub = recompute_root(leaf, m - k, n - k, inner)?;
        Some(hash_inner(&top_sibling, &sub))
    }
}

/// Largest power of two strictly less than `n`. Caller guarantees `n >= 2`.
fn largest_pow2_lt(n: usize) -> usize {
    debug_assert!(n >= 2);
    let highest = usize::BITS - (n - 1).leading_zeros() - 1;
    1usize << highest
}

fn hash_inner(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([INNER_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}
