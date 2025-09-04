//! HTTP client to test the superblock proof server
//!
//! You can run this client using:
//! ```shell
//! cargo run --bin client
//! ```

use clap::Parser;
use reqwest::Client;
use serde_json::json;
use superblock_lib::{Superblock, L2Block};

/// The arguments for the client.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "http://localhost:3000")]
    server_url: String,

    #[arg(long, default_value = "execute")]
    proof_type: String,
}

/// Create sample superblock data for testing (same as server)
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let client = Client::new();

    println!("Testing superblock proof server at {}", args.server_url);

    // Test health endpoint
    println!("\n1. Testing health endpoint...");
    let health_response = client
        .get(&format!("{}/health", args.server_url))
        .send()
        .await?;
    
    if health_response.status().is_success() {
        let health_data: serde_json::Value = health_response.json().await?;
        println!("[OK] Health check: {}", health_data);
    } else {
        println!("[ERROR] Health check failed: {}", health_response.status());
        return Ok(());
    }

    // Test async proof submission
    println!("\n2. Testing async proof submission with {} proof...", args.proof_type);
    let (prev_superblock, new_superblock) = create_sample_superblocks();
    
    let proof_request = json!({
        "prev_superblock": prev_superblock,
        "new_superblock": new_superblock,
        "proof_type": args.proof_type.to_lowercase()
    });

    println!("   Submitting proof request...");
    let submission_response = client
        .post(&format!("{}/proof", args.server_url))
        .header("Content-Type", "application/json")
        .json(&proof_request)
        .send()
        .await?;

    if submission_response.status().is_success() {
        let submission_data: serde_json::Value = submission_response.json().await?;
        
        if submission_data["success"].as_bool().unwrap_or(false) {
            let request_id = submission_data["request_id"].as_str().unwrap();
            println!("[OK] Proof request submitted");
            println!("   Request ID: {}", request_id);
            
            // Poll for result
            println!("\n3. Polling for proof result...");
            let mut attempts = 0;
            let max_attempts = 90; // Wait up to 5 minutes (60 * 5 seconds)
            
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                attempts += 1;
                
                let result_response = client
                    .get(&format!("{}/proof/{}", args.server_url, request_id))
                    .send()
                    .await?;
                
                if result_response.status().is_success() {
                    let result_data: serde_json::Value = result_response.json().await?;
                    let status = result_data["status"].as_str().unwrap_or("unknown");
                    
                    println!("   Status: {} (attempt {}/{})", status, attempts, max_attempts);
                    
                    match status {
                        "completed" => {
                            println!("[OK] Proof generation completed");
                            
                            if let Some(result) = result_data["result"].as_object() {
                                println!("   Results:");
                                
                                if let Some(cycles) = result.get("cycles").and_then(|c| c.as_u64()) {
                                    println!("     Cycles: {}", cycles);
                                }
                                
                                if let Some(time_ms) = result.get("proving_time_ms").and_then(|t| t.as_u64()) {
                                    println!("     Proving time: {}ms", time_ms);
                                }
                                
                                if let Some(proof_bytes) = result.get("proof").and_then(|p| p.as_array()) {
                                    println!("     Proof size: {} bytes", proof_bytes.len());
                                    if !proof_bytes.is_empty() {
                                        // Convert JSON numbers to bytes and then to hex
                                        let bytes: Vec<u8> = proof_bytes.iter()
                                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                                            .collect();
                                        let hex_str = hex::encode(&bytes);
                                        println!("     Proof (full hex): {}", hex_str);
                                    }
                                }
                            }
                            break;
                        }
                        "failed" => {
                            println!("[ERROR] Proof generation failed");
                            if let Some(error) = result_data["error"].as_str() {
                                println!("   Error: {}", error);
                            }
                            break;
                        }
                        "pending" | "running" => {
                            if attempts >= max_attempts {
                                println!("[TIMEOUT] Proof generation timed out after {} attempts", max_attempts);
                                break;
                            }
                            // Continue polling
                        }
                        _ => {
                            println!("[ERROR] Unknown status: {}", status);
                            break;
                        }
                    }
                } else {
                    println!("[ERROR] Failed to fetch result: {}", result_response.status());
                    break;
                }
            }
        } else {
            println!("[ERROR] Proof submission failed");
            if let Some(error) = submission_data["error"].as_str() {
                println!("   Error: {}", error);
            }
        }
    } else {
        println!("[ERROR] Proof submission endpoint failed: {}", submission_response.status());
        let error_text = submission_response.text().await?;
        println!("   Error: {}", error_text);
    }

    println!("\n[DONE] Client test completed!");
    Ok(())
}
