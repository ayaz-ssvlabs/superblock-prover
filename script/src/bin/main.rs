//! An end-to-end example of using the SP1 SDK to generate proofs of superblock transition verification.
//!
//! You can run this script using one of the following commands:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```
//! ```shell
//! RUST_LOG=info cargo run --release -- --groth16
//! ```
//! ```shell
//! cargo run --release -- --groth16 --verbose
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use superblock_lib::{PublicValuesStruct, Superblock, L2Block};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::time::Instant;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const SUPERBLOCK_ELF: &[u8] = include_elf!("superblock-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long)]
    groth16: bool,

    #[arg(long)]
    verbose: bool,
}

/// Create sample superblock data for testing
fn create_sample_superblocks() -> (Superblock, Superblock) {
    // Create some sample L2 blocks for the new superblock
    let l2_blocks = vec![
        L2Block {
            slot: 100,
            chain_id: b"chain1".to_vec(),
            block_number: 1001,
            block_hash: vec![0x11; 32],
            parent_block_hash: vec![0x10; 32],
            included_xts: vec![vec![0x01, 0x02, 0x03]],
            block: vec![0xaa; 100], // Sample RLP encoded block
        },
        L2Block {
            slot: 100,
            chain_id: b"chain2".to_vec(),
            block_number: 2001,
            block_hash: vec![0x21; 32],
            parent_block_hash: vec![0x20; 32],
            included_xts: vec![vec![0x04, 0x05, 0x06]],
            block: vec![0xbb; 100],
        },
    ];

    // Calculate merkle root for the L2 blocks
    let merkle_root = superblock_lib::calculate_merkle_root(&l2_blocks);

    // Previous superblock
    let prev_superblock = Superblock {
        number: 99,
        slot: 99,
        parent_hash: vec![0x99; 32],
        hash: vec![0x00; 32], // Will be calculated
        merkle_root: vec![0x88; 32],
        timestamp: 1000000,
        l2_blocks: vec![],
        included_xts: vec![],
        l1_transaction_hash: Some(vec![0x77; 32]),
    };

    // Calculate the previous superblock hash
    let prev_hash = superblock_lib::calculate_superblock_hash(&prev_superblock);

    // New superblock (should be a valid transition)
    let new_superblock = Superblock {
        number: 100, // prev + 1
        slot: 100,   // >= prev slot
        parent_hash: prev_hash.clone(), // Must match prev hash
        hash: vec![0x00; 32], // Will be calculated
        merkle_root,
        timestamp: 1000001, // Must be > prev timestamp
        l2_blocks,
        included_xts: vec![vec![0x07, 0x08, 0x09]],
        l1_transaction_hash: Some(vec![0x66; 32]),
    };

    (prev_superblock, new_superblock)
}

fn main() {
    // Parse the command line arguments first to check for verbose flag.
    let args = Args::parse();
    
    // Setup the logger with appropriate level.
    if args.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Validate argument combinations
    let actions_count = [args.execute, args.prove, args.groth16].iter().filter(|&&x| x).count();
    if actions_count != 1 {
        eprintln!("Error: You must specify exactly one of --execute, --prove, or --groth16");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    // Create sample superblock data
    let (prev_superblock, new_superblock) = create_sample_superblocks();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&prev_superblock);
    stdin.write(&new_superblock);

    println!("Previous superblock number: {}", prev_superblock.number);
    println!("New superblock number: {}", new_superblock.number);
    println!("L2 blocks in new superblock: {}", new_superblock.l2_blocks.len());

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(SUPERBLOCK_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        let PublicValuesStruct { 
            prev_superblock_hash,
            new_superblock_hash,
            prev_number,
            new_number,
            is_valid_transition,
        } = decoded;

        println!("Previous superblock hash: 0x{}", hex::encode(prev_superblock_hash));
        println!("New superblock hash: 0x{}", hex::encode(new_superblock_hash));
        println!("Previous number: {}", prev_number);
        println!("New number: {}", new_number);
        println!("Is valid transition: {}", is_valid_transition);

        // Verify the transition outside the zkVM as well
        let (expected_prev_hash, expected_new_hash, expected_valid) = 
            superblock_lib::verify_superblock_transition(&prev_superblock, &new_superblock);
            
        // Convert to fixed arrays for comparison
        let mut expected_prev_32 = [0u8; 32];
        let mut expected_new_32 = [0u8; 32];
        expected_prev_32.copy_from_slice(&expected_prev_hash[..32]);
        expected_new_32.copy_from_slice(&expected_new_hash[..32]);

        assert_eq!(prev_superblock_hash, expected_prev_32);
        assert_eq!(new_superblock_hash, expected_new_32);
        assert_eq!(is_valid_transition, expected_valid);
        println!("Verification results match!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else if args.prove {
        // Setup the program for proving (STARK proof).
        let (pk, vk) = client.setup(SUPERBLOCK_ELF);

        // Generate the STARK proof
        println!("Generating STARK proof...");
        let start_time = Instant::now();
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate STARK proof");
        let proof_time = start_time.elapsed();

        println!("Successfully generated STARK proof!");
        println!("Proof generation time: {:.2?}", proof_time);
        println!("Proof size: {} bytes", proof.bytes().len());

        // Verify the proof.
        let verify_start = Instant::now();
        client.verify(&proof, &vk).expect("failed to verify STARK proof");
        let verify_time = verify_start.elapsed();
        println!("Successfully verified STARK proof!");
        println!("Verification time: {:.2?}", verify_time);
    } else if args.groth16 {
        // Setup the program for Groth16 proving.
        let (pk, vk) = client.setup(SUPERBLOCK_ELF);

        // Generate the Groth16 proof
        println!("Generating Groth16 proof (this may take several minutes)...");
        let start_time = Instant::now();
        let proof = client
            .prove(&pk, &stdin)
            .groth16()
            .run()
            .expect("failed to generate Groth16 proof");
        let proof_time = start_time.elapsed();

        println!("Successfully generated Groth16 proof!");
        println!("Proof generation time: {:.2?}", proof_time);
        println!("Proof size: {} bytes", proof.bytes().len());

        // Print the proof in hex format
        println!("Proof (hex): 0x{}", hex::encode(proof.bytes()));

        // Verify the Groth16 proof.
        let verify_start = Instant::now();
        client.verify(&proof, &vk).expect("failed to verify Groth16 proof");
        let verify_time = verify_start.elapsed();
        println!("Successfully verified Groth16 proof!");
        println!("Verification time: {:.2?}", verify_time);

        // Extract and display public values
        let decoded = PublicValuesStruct::abi_decode(proof.public_values.as_slice()).unwrap();
        let PublicValuesStruct { 
            prev_superblock_hash,
            new_superblock_hash,
            prev_number,
            new_number,
            is_valid_transition,
        } = decoded;

        println!("\nPublic Values from Groth16 proof:");
        println!("Previous superblock hash: 0x{}", hex::encode(prev_superblock_hash));
        println!("New superblock hash: 0x{}", hex::encode(new_superblock_hash));
        println!("Previous number: {}", prev_number);
        println!("New number: {}", new_number);
        println!("Is valid transition: {}", is_valid_transition);
    }
}
