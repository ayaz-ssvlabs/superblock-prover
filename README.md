# SP1 Superblock Verification

This project uses [SP1](https://github.com/succinctlabs/sp1) to generate zero-knowledge proofs
for superblock transition verification, ensuring cryptographic validity of blockchain state transitions.

## Requirements

- [Rust](https://rustup.rs/)
- [SP1](https://docs.succinct.xyz/docs/sp1/getting-started/install)

## Running the Project

This project verifies superblock transitions using zero-knowledge proofs. There are 2 main ways to run this project: execute verification directly, or generate a cryptographic proof.

### Build the Program

The program is automatically built through `script/build.rs` when the script is built.

### Execute Superblock Verification

To run the superblock verification without generating a proof:

```sh
cd script
cargo run --release --bin superblock -- --execute
```

This will execute the superblock transition verification and display the results, including:
- Previous and new superblock hashes
- Verification of transition rules (number increment, parent hash matching, Merkle root validation)
- Confirmation of valid state transition

### Generate an SP1 Core Proof

To generate an SP1 [core proof](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types#core-default) for superblock verification:

```sh
cd script
cargo run --release --bin superblock -- --prove
```

## Superblock Verification Features

This implementation includes:

- **Merkle Root Calculation**: Computes Merkle trees from L2 blocks with deterministic ordering
- **Superblock Hash Validation**: Implements the exact hash calculation logic (Number || Slot || ParentHash || MerkleRoot)
- **Transition Rule Verification**: Ensures valid state transitions between superblocks:
  - Sequential number increment (new = prev + 1)
  - Parent hash matching
  - Slot monotonicity
  - Merkle root correctness
  - Timestamp progression
- **Zero-Knowledge Proofs**: Generates cryptographic proofs of valid transitions
- **Solidity Compatibility**: Outputs are ABI-encoded for on-chain verification

## Data Structures

The verification handles the following superblock structure:
- `number`: Superblock sequence number
- `slot`: Blockchain slot number
- `parent_hash`: Hash of the previous superblock
- `merkle_root`: Root of the L2 blocks Merkle tree
- `l2_blocks`: Array of L2 blocks with cross-chain transactions
- `timestamp`: Block timestamp for monotonicity checks

## Using the Prover Network

We highly recommend using the [Succinct Prover Network](https://docs.succinct.xyz/docs/network/introduction) for any non-trivial programs or benchmarking purposes. For more information, see the [key setup guide](https://docs.succinct.xyz/docs/network/developers/key-setup) to get started.

To get started, copy the example environment file:

```sh
cp .env.example .env
```

Then, set the `SP1_PROVER` environment variable to `network` and set the `NETWORK_PRIVATE_KEY`
environment variable to your whitelisted private key.

For example, to generate a superblock verification proof using the prover network, run the following
command:

```sh
SP1_PROVER=network NETWORK_PRIVATE_KEY=... cargo run --release --bin superblock -- --prove
```
