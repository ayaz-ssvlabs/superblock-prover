//! An end-to-end example of using the SP1 SDK to generate proofs of superblock transition verification.
//!
//! You can run this script using one of the following commands:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! ```shell
//! RUST_LOG=info cargo run --release -- --groth16
//! ```
//! ```shell
//! cargo run --release -- --groth16 --verbose
//! ```
//! ```shell
//! cargo run --release -- --server --port 3000
//! ```

use alloy_sol_types::SolType;
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::Json as ResponseJson,
    routing::{get, post},
    Router,
};
use clap::Parser;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use superblock_lib::{PublicValuesStruct, Superblock, L2Block};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use tokio::task;
use tower_http::cors::CorsLayer;
use tracing::{debug, info, warn, error};
use uuid::Uuid;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const SUPERBLOCK_ELF: &[u8] = include_elf!("superblock-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    groth16: bool,

    #[arg(long)]
    verbose: bool,

    #[arg(long)]
    server: bool,

    #[arg(long, default_value = "3000")]
    port: u16,
}

/// Request structure for HTTP API
#[derive(Debug, Deserialize)]
struct ProofRequest {
    prev_superblock: Superblock,
    new_superblock: Superblock,
    proof_type: ProofType,
}

/// Proof type enum
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ProofType {
    Execute,
    Groth16,
}

/// Response structure for async proof submission
#[derive(Debug, Serialize)]
struct ProofSubmissionResponse {
    success: bool,
    message: String,
    request_id: Option<String>,
    error: Option<String>,
}

/// Response structure for proof result fetching
#[derive(Debug, Serialize)]
struct ProofResultResponse {
    success: bool,
    status: ProofStatus,
    result: Option<ProofResult>,
    error: Option<String>,
}

/// Proof result structure (simplified as requested)
#[derive(Debug, Serialize, Clone)]
struct ProofResult {
    proof: Option<Vec<u8>>,
    proving_time_ms: Option<u64>,
    cycles: Option<u64>,
}

/// Proof status enum
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
enum ProofStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

/// Internal proof job structure
#[derive(Debug, Clone)]
struct ProofJob {
    request_id: String,
    status: ProofStatus,
    result: Option<ProofResult>,
    error: Option<String>,
    created_at: Instant,
}

/// Application state
#[derive(Clone)]
struct AppState {
    jobs: Arc<DashMap<String, ProofJob>>,
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

/// Handle async proof submission
async fn submit_proof(
    State(state): State<AppState>,
    Json(payload): Json<ProofRequest>
) -> Result<ResponseJson<ProofSubmissionResponse>, StatusCode> {
    info!("Received proof request: {:?} (prev_block: {}, new_block: {})", 
          payload.proof_type, payload.prev_superblock.number, payload.new_superblock.number);
    
    // Generate unique request ID
    let request_id = Uuid::new_v4().to_string();
    
    debug!("L2 blocks in new superblock: {}", payload.new_superblock.l2_blocks.len());
    
    // Create initial job entry
    let job = ProofJob {
        request_id: request_id.clone(),
        status: ProofStatus::Pending,
        result: None,
        error: None,
        created_at: Instant::now(),
    };
    
    state.jobs.insert(request_id.clone(), job);
    
    // Spawn background task to process the proof
    let jobs = state.jobs.clone();
    let job_id = request_id.clone();
    info!("Proof request with {} id submitted", job_id);
    task::spawn(async move {
        process_proof_job(jobs, job_id, payload).await;
    });
    
    Ok(ResponseJson(ProofSubmissionResponse {
        success: true,
        message: "Proof request submitted successfully".to_string(),
        request_id: Some(request_id),
        error: None,
    }))
}

/// Process proof job in background
async fn process_proof_job(
    jobs: Arc<DashMap<String, ProofJob>>,
    request_id: String,
    payload: ProofRequest,
) {
    // Update status to running
    if let Some(mut job) = jobs.get_mut(&request_id) {
        job.status = ProofStatus::Running;
    }
    
    let start_time = Instant::now();
    
    // Setup the prover client using SP1_PROVER environment variable (defaults to "cpu")
    let sp1_prover = std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".to_string());
    info!("Using SP1_PROVER: {} for request {}", sp1_prover, request_id);
    
    let client = ProverClient::from_env();
    
    // Setup the inputs
    let mut stdin = SP1Stdin::new();
    stdin.write(&payload.prev_superblock);
    stdin.write(&payload.new_superblock);
    
    let result = match payload.proof_type {
        ProofType::Execute => {
            match client.execute(SUPERBLOCK_ELF, &stdin).run() {
                Ok((_, report)) => {
                    info!("Execution completed for request {}", request_id);
                    Ok(ProofResult {
                        proof: None, // No proof for execution
                        proving_time_ms: Some(start_time.elapsed().as_millis() as u64),
                        cycles: Some(report.total_instruction_count()),
                    })
                }
                Err(e) => {
                    error!("Execution failed for request {}: {}", request_id, e);
                    Err(e.to_string())
                }
            }
        }
        ProofType::Groth16 => {
            match client.setup(SUPERBLOCK_ELF) {
                (pk, _vk) => {
                    match client.prove(&pk, &stdin).groth16().run() {
                        Ok(proof) => {
                            info!("Groth16 proof generated for request {}", request_id);
                            
                            // For Groth16, we need to run execution separately to get cycles
                            // since the proof generation doesn't provide execution statistics
                            let cycles = match client.execute(SUPERBLOCK_ELF, &stdin).run() {
                                Ok((_, report)) => Some(report.total_instruction_count()),
                                Err(_) => {
                                    warn!("Could not get cycles for Groth16 proof {}", request_id);
                                    None
                                }
                            };
                            
                            Ok(ProofResult {
                                proof: Some(proof.bytes().to_vec()),
                                proving_time_ms: Some(start_time.elapsed().as_millis() as u64),
                                cycles,
                            })
                        }
                        Err(e) => {
                            error!("Groth16 proof generation failed for request {}: {}", request_id, e);
                            Err(e.to_string())
                        }
                    }
                }
            }
        }
    };
    
    // Update job with result
    if let Some(mut job) = jobs.get_mut(&request_id) {
        match result {
            Ok(proof_result) => {
                job.status = ProofStatus::Completed;
                job.result = Some(proof_result.clone());
                info!("Job {} completed successfully", request_id);
                
                // Log additional details about the completed proof
                if let Some(proof_bytes) = &proof_result.proof {
                    let proof_hex = hex::encode(proof_bytes);
                    info!("Proof: {}", proof_hex);
                    info!("Proof size: {} bytes", proof_bytes.len());
                }
                
                // if let Some(cycles) = proof_result.cycles {
                //     info!("Execution cycles: {}", cycles);
                // }
                
                if let Some(time_ms) = proof_result.proving_time_ms {
                    let time_seconds = time_ms as f64 / 1000.0;
                    info!("Proving time: {:.2}s", time_seconds);
                }
            }
            Err(error_msg) => {
                job.status = ProofStatus::Failed;
                job.error = Some(error_msg);
                warn!("Job {} failed", request_id);
            }
        }
    }
}

/// Get proof result by request ID
async fn get_proof_result(
    State(state): State<AppState>,
    Path(request_id): Path<String>
) -> Result<ResponseJson<ProofResultResponse>, StatusCode> {
    debug!("Fetching result for request {}", request_id);
    
    if let Some(job) = state.jobs.get(&request_id) {
        Ok(ResponseJson(ProofResultResponse {
            success: true,
            status: job.status.clone(),
            result: job.result.clone(),
            error: job.error.clone(),
        }))
    } else {
        Ok(ResponseJson(ProofResultResponse {
            success: false,
            status: ProofStatus::Failed,
            result: None,
            error: Some("Request not found".to_string()),
        }))
    }
}

/// Health check endpoint
async fn health() -> ResponseJson<serde_json::Value> {
    ResponseJson(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().timestamp()
    }))
}


/// Start the HTTP server
async fn start_server(port: u16) {
    let state = AppState {
        jobs: Arc::new(DashMap::new()),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/proof", post(submit_proof))
        .route("/proof/:request_id", get(get_proof_result))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
        
    info!("Server running on http://0.0.0.0:{}", port);
    info!("Endpoints:");
    info!("  GET  /health - Health check");
    info!("  POST /proof  - Submit proof request (async)");
    info!("  GET  /proof/:request_id - Get proof result");
    
    axum::serve(listener, app).await.unwrap();
}

#[tokio::main]
async fn main() {
    // Parse the command line arguments first to check for verbose flag.
    let args = Args::parse();
    
    // Setup the logger with appropriate level.
    if args.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Check if server mode is requested
    if args.server {
        start_server(args.port).await;
        return;
    }

    // Validate argument combinations for non-server mode
    let actions_count = [args.execute, args.groth16].iter().filter(|&&x| x).count();
    if actions_count != 1 {
        eprintln!("Error: You must specify exactly one of --execute, --groth16, or --server");
        std::process::exit(1);
    }

    // Setup the prover client using SP1_PROVER environment variable (defaults to "cpu")
    let sp1_prover = std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".to_string());
    println!("Using SP1_PROVER: {}", sp1_prover);
    
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

