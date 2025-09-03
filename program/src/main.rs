//! A program that verifies superblock transitions in a zkVM environment.
//! Takes two superblocks as input and verifies the transition is valid.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use superblock_lib::{verify_superblock_transition, PublicValuesStruct, Superblock};

pub fn main() {
    // Read the previous superblock from the prover input
    let prev_superblock = sp1_zkvm::io::read::<Superblock>();

    // Read the new superblock from the prover input
    let new_superblock = sp1_zkvm::io::read::<Superblock>();

    // Verify the superblock transition
    let (prev_hash, new_hash, is_valid) =
        verify_superblock_transition(&prev_superblock, &new_superblock);

    // Convert hashes to fixed-size arrays for Solidity compatibility
    let mut prev_hash_32 = [0u8; 32];
    let mut new_hash_32 = [0u8; 32];

    // Copy the hash bytes (should be exactly 32 bytes from Keccak256)
    prev_hash_32.copy_from_slice(&prev_hash[..32]);
    new_hash_32.copy_from_slice(&new_hash[..32]);

    // Encode the public values of the program
    let public_values = PublicValuesStruct {
        prev_superblock_hash: prev_hash_32.into(),
        new_superblock_hash: new_hash_32.into(),
        prev_number: prev_superblock.number,
        new_number: new_superblock.number,
        is_valid_transition: is_valid,
    };

    let bytes = PublicValuesStruct::abi_encode(&public_values);

    // Commit to the public values of the program. The final proof will have a commitment to all the
    // bytes that were committed to.
    sp1_zkvm::io::commit_slice(&bytes);
}
