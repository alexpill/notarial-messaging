// Append-only Merkle transparency log.
// Each message produces a leaf: SHA256(signature || acte_uuid || timestamp || seq).
// The root can be signed by the EN to prove a message existed at a given time,
// without revealing its content (which stays encrypted).

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// Inclusion proof for a single leaf.
/// Contains the sibling hashes needed to recompute the root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    /// Sibling hashes from leaf level up to root.
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

    /// Compute the current Merkle root. Returns None if the log is empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.leaves.is_empty() {
            return None;
        }
        Some(compute_root(&self.leaves))
    }

    /// Generate an inclusion proof for the leaf at `leaf_index`.
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut nodes = self.leaves.clone();
        let mut index = leaf_index;

        while nodes.len() > 1 {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            // Odd tree: duplicate the last node rather than leaving a gap.
            let sibling = if sibling_index < nodes.len() {
                nodes[sibling_index]
            } else {
                nodes[index]
            };
            siblings.push(sibling);

            nodes = nodes
                .chunks(2)
                .map(|pair| hash_pair(&pair[0], pair.get(1).unwrap_or(&pair[0])))
                .collect();
            index /= 2;
        }

        Some(MerkleProof { leaf_index, siblings })
    }

    /// Verify that `leaf` is included in a tree with the given `root`.
    pub fn verify_proof(root: &[u8; 32], leaf: &[u8; 32], proof: &MerkleProof) -> bool {
        let mut current = *leaf;
        let mut index = proof.leaf_index;

        for sibling in &proof.siblings {
            current = if index % 2 == 0 {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
            index /= 2;
        }

        &current == root
    }
}

/// Compute the leaf hash for a single message without appending to any log.
pub fn leaf_hash(
    signature: &ed25519_dalek::Signature,
    acte_uuid: &uuid::Uuid,
    timestamp: i64,
    seq: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(signature.to_bytes());
    hasher.update(acte_uuid.as_bytes());
    hasher.update(timestamp.to_le_bytes());
    hasher.update(seq.to_le_bytes());
    hasher.finalize().into()
}

fn compute_root(nodes: &[[u8; 32]]) -> [u8; 32] {
    if nodes.len() == 1 {
        return nodes[0];
    }
    let next: Vec<[u8; 32]> = nodes
        .chunks(2)
        .map(|pair| hash_pair(&pair[0], pair.get(1).unwrap_or(&pair[0])))
        .collect();
    compute_root(&next)
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}
