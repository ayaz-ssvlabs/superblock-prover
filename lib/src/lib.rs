use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

sol! {
    /// The public values for superblock transition verification
    struct PublicValuesStruct {
        bytes32 prev_superblock_hash;
        bytes32 new_superblock_hash;
        uint64 prev_number;
        uint64 new_number;
        bool is_valid_transition;
    }
}

/// Represents an L2 Block as defined in the protobuf schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Block {
    pub slot: u64,
    pub chain_id: Vec<u8>,
    pub block_number: u64,
    pub block_hash: Vec<u8>,
    pub parent_block_hash: Vec<u8>,
    pub included_xts: Vec<Vec<u8>>,
    pub block: Vec<u8>, // RLP encoded block data
}

/// Represents a Superblock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Superblock {
    pub number: u64,
    pub slot: u64,
    pub parent_hash: Vec<u8>,
    pub hash: Vec<u8>,
    pub merkle_root: Vec<u8>,
    pub timestamp: u64, // Unix timestamp instead of time.Time for simplicity
    pub l2_blocks: Vec<L2Block>,
    pub included_xts: Vec<Vec<u8>>,
    pub l1_transaction_hash: Option<Vec<u8>>,
}

/// Calculate the Merkle root from L2 blocks
pub fn calculate_merkle_root(blocks: &[L2Block]) -> Vec<u8> {
    if blocks.is_empty() {
        return vec![0u8; 32];
    }

    // Sort blocks by chain_id (lexicographic)
    let mut sorted_blocks = blocks.to_vec();
    sorted_blocks.sort_by(|a, b| a.chain_id.cmp(&b.chain_id));

    // Compute leaf hashes = keccak256(chainID || blockHash || blockNumberBE)
    let mut leaves: Vec<Vec<u8>> = Vec::new();
    for block in &sorted_blocks {
        let mut buf = Vec::new();
        buf.extend_from_slice(&block.chain_id);
        buf.extend_from_slice(&block.block_hash);
        buf.extend_from_slice(&block.block_number.to_be_bytes());

        let hash = Keccak256::digest(&buf);
        leaves.push(hash.to_vec());
    }

    // Build Merkle tree with keccak256(left||right), duplicate last when odd
    let mut level = leaves;
    while level.len() > 1 {
        let mut next_level = Vec::new();
        for i in (0..level.len()).step_by(2) {
            let left = &level[i];
            let right = if i + 1 < level.len() {
                &level[i + 1]
            } else {
                left // Duplicate last when odd
            };

            let mut combined = Vec::new();
            combined.extend_from_slice(left);
            combined.extend_from_slice(right);

            let hash = Keccak256::digest(&combined);
            next_level.push(hash.to_vec());
        }
        level = next_level;
    }

    level[0].clone()
}

/// Calculate the superblock hash
pub fn calculate_superblock_hash(superblock: &Superblock) -> Vec<u8> {
    // Header fields: Number || Slot || ParentHash || MerkleRoot
    let mut header = Vec::new();
    header.extend_from_slice(&superblock.number.to_be_bytes());
    header.extend_from_slice(&superblock.slot.to_be_bytes());
    header.extend_from_slice(&superblock.parent_hash);
    header.extend_from_slice(&superblock.merkle_root);

    let hash = Keccak256::digest(&header);
    hash.to_vec()
}

/// Verify a superblock transition
pub fn verify_superblock_transition(
    prev_superblock: &Superblock,
    new_superblock: &Superblock,
) -> (Vec<u8>, Vec<u8>, bool) {
    // Calculate hashes
    let prev_hash = calculate_superblock_hash(prev_superblock);
    let new_hash = calculate_superblock_hash(new_superblock);

    // Verify the transition is valid
    let is_valid = verify_transition_rules(prev_superblock, new_superblock, &prev_hash);

    (prev_hash, new_hash, is_valid)
}

/// Verify superblock transition rules
fn verify_transition_rules(
    prev_superblock: &Superblock,
    new_superblock: &Superblock,
    prev_hash: &[u8],
) -> bool {
    // Rule 1: New superblock number must be prev + 1
    if new_superblock.number != prev_superblock.number + 1 {
        return false;
    }

    // Rule 2: New superblock's parent_hash must match prev superblock's hash
    if new_superblock.parent_hash != prev_hash {
        return false;
    }

    // Rule 3: New superblock's slot must be >= prev superblock's slot
    if new_superblock.slot < prev_superblock.slot {
        return false;
    }

    // Rule 4: Verify merkle root is correctly calculated
    let calculated_merkle_root = calculate_merkle_root(&new_superblock.l2_blocks);
    if new_superblock.merkle_root != calculated_merkle_root {
        return false;
    }

    // Rule 5: Timestamp must be increasing (basic check)
    if new_superblock.timestamp <= prev_superblock.timestamp {
        return false;
    }

    true
}
