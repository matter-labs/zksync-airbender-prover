//! File-based reproduction of the SNARK prover pipeline.
//!
//! Accepts either input format (auto-detected):
//!  - sequencer SNARK job payload (`GetSnarkProofPayload`): from/to batch numbers,
//!    vk_hash and base64(bincode) FRI proofs - as returned by the prover API
//!    pick/peek SNARK job endpoints;
//!  - batch envelope JSON as stored by zksync-os-server: FRI `ProgramProof` in
//!    `V1.data.Real.proof` (0x-hex of bincode bytes).
//!
//! Runs the same pipeline as `run_inner`:
//!   merge_fris (no-op for a single proof)
//!     -> create_final_proofs_from_program_proof (UseReducedLog23Machine)
//!     -> zkos_wrapper::prove (risc wrapper -> compression -> snark wrapper)
//!
//! Usage (from zksync-airbender-prover root):
//!   RUST_MIN_STACK=267108864 cargo run --release --features gpu --bin snark_repro -- \
//!     --batch-file ../batch_204254.json \
//!     --binary-path ./multiblock_batch.bin \
//!     --trusted-setup-file ../zksync-airbender-prover-private/crs/setup_compact.key \
//!     --output-dir ./outputs

use clap::Parser;
use std::path::Path;
use zkos_wrapper::{prove, serialize_to_file};
use zksync_airbender_cli::prover_utils::create_final_proofs_from_program_proof;
use zksync_airbender_execution_utils::{
    get_padded_binary, ProgramProof, RecursionStrategy, UNIVERSAL_CIRCUIT_VERIFIER,
};
use zksync_os_snark_prover::merge_fris;
use zksync_sequencer_proof_client::{L2BatchNumber, SnarkProofInputs};

#[derive(Parser)]
struct Args {
    /// Path to the batch envelope JSON (SignedBatchEnvelope<FriProof>)
    #[arg(long)]
    batch_file: String,

    /// Path to the zksync-os app binary (multiblock_batch.bin)
    #[arg(long, default_value = "./multiblock_batch.bin")]
    binary_path: String,

    #[arg(long, default_value = "./outputs")]
    output_dir: String,

    #[arg(long)]
    trusted_setup_file: String,

    /// Stop after creating the final FRI proof (skip the SNARK stage)
    #[arg(long, default_value_t = false)]
    skip_snark: bool,

    /// Stop after creating and verifying the RISC wrapper proof
    #[arg(long, default_value_t = false)]
    risc_wrapper_only: bool,

    /// Skip the final-proof recursion step and SNARKify the input proof directly
    /// (only valid if the input is already a final proof)
    #[arg(long, default_value_t = false)]
    skip_final_proof: bool,

    /// Preserve the older repro ordering: defer SNARK precomputations until after the final proof
    #[arg(long, default_value_t = false)]
    legacy_order: bool,

    /// Preserve the older repro behavior: do not initialize merge GPU state for a single proof
    #[arg(long, default_value_t = false)]
    lazy_merge_gpu_state: bool,

    #[arg(long, default_value_t = false)]
    disable_zk: bool,
}

fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

fn decode_program_proof(bytes: &[u8]) -> ProgramProof {
    println!("FRI proof: {} bytes (bincode)", bytes.len());
    let (proof, consumed): (ProgramProof, usize) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .expect("failed to bincode-decode ProgramProof");
    assert_eq!(consumed, bytes.len(), "trailing bytes after ProgramProof");
    proof
}

fn load_snark_proof_inputs(path: &str) -> SnarkProofInputs {
    let file = std::fs::File::open(path).expect("failed to open batch file");
    let v: serde_json::Value = serde_json::from_reader(file).expect("invalid JSON");

    // sequencer SNARK job payload (GetSnarkProofPayload)
    if let Some(fri_proofs) = v.get("fri_proofs").and_then(|p| p.as_array()) {
        let from = v["from_batch_number"].as_u64().expect("from_batch_number") as u32;
        let to = v["to_batch_number"].as_u64().expect("to_batch_number") as u32;
        let vk_hash = v["vk_hash"].as_str().expect("vk_hash").to_string();
        println!("SNARK job payload: batches [{from}..{to}], vk_hash {vk_hash}");
        let fri_proofs = fri_proofs
            .iter()
            .map(|p| {
                let bytes = base64_decode(p.as_str().expect("fri_proofs[i] must be a string"));
                decode_program_proof(&bytes)
            })
            .collect();
        return SnarkProofInputs {
            from_batch_number: L2BatchNumber(from),
            to_batch_number: L2BatchNumber(to),
            vk_hash,
            fri_proofs,
        };
    }

    // batch envelope as stored by zksync-os-server
    let hex_proof = v
        .pointer("/V1/data/Real/proof")
        .and_then(|p| p.as_str())
        .expect("file is neither a SNARK job payload nor a V1 batch envelope");
    if let Some(version) = v.pointer("/V1/data/Real/proving_execution_version") {
        println!("proving_execution_version: {version}");
    }
    let batch = v
        .pointer("/V1/batch/commit_batch_info/batch_number")
        .and_then(|b| b.as_u64())
        .unwrap_or(0) as u32;
    SnarkProofInputs {
        from_batch_number: L2BatchNumber(batch),
        to_batch_number: L2BatchNumber(batch),
        vk_hash: String::new(),
        fri_proofs: vec![decode_program_proof(&decode_hex(hex_proof))],
    }
}

const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode(s: &str) -> Vec<u8> {
    let mut table = [255u8; 256];
    for (i, &c) in BASE64_ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in s.as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = table[c as usize];
        assert!(v != 255, "invalid base64 character: {}", c as char);
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn print_proof_info(tag: &str, proof: &ProgramProof) {
    println!("=== {tag} ===");
    println!("  base_layer_proofs: {}", proof.base_layer_proofs.len());
    println!(
        "  delegation_proofs: {:?}",
        proof
            .delegation_proofs
            .iter()
            .map(|(k, v)| (*k, v.len()))
            .collect::<Vec<_>>()
    );
    println!("  end_params: {:08x?}", proof.end_params);
    println!(
        "  recursion_chain_preimage: {:08x?}",
        proof.recursion_chain_preimage
    );
    println!(
        "  recursion_chain_hash: {:08x?}",
        proof.recursion_chain_hash
    );
    let (metadata, _) = proof.clone().to_metadata_and_proof_list();
    println!(
        "  metadata: basic={} reduced={} reduced_log_23={} delegation={:?}",
        metadata.basic_proof_count,
        metadata.reduced_proof_count,
        metadata.reduced_log_23_proof_count,
        metadata.delegation_proof_count,
    );
    println!(
        "  final register values: {:08x?}",
        proof
            .register_final_values
            .iter()
            .map(|r| r.value)
            .collect::<Vec<_>>()
    );
}

fn main() {
    let args = Args::parse();

    // crypto code needs a big stack; mirror the prover's RUST_MIN_STACK setup
    let handle = std::thread::Builder::new()
        .stack_size(400 * 1024 * 1024)
        .spawn(move || run(args))
        .unwrap();
    handle.join().unwrap();
}

fn run(args: Args) {
    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    #[cfg(feature = "gpu")]
    let early_precomputations = if !args.skip_snark && !args.risc_wrapper_only && !args.legacy_order
    {
        println!("Computing SNARK precomputations before job processing");
        let compression_vk =
            zksync_os_snark_prover::compute_compression_vk(args.binary_path.clone());
        let precomputations = zkos_wrapper::gpu::snark::gpu_create_snark_setup_data(
            &compression_vk,
            &args.trusted_setup_file,
        );
        println!("Finished computing SNARK precomputations");
        Some(precomputations)
    } else {
        None
    };

    let snark_proof_input = load_snark_proof_inputs(&args.batch_file);
    for (i, proof) in snark_proof_input.fri_proofs.iter().enumerate() {
        print_proof_info(&format!("input FRI proof {i}"), proof);
    }

    #[cfg(feature = "gpu")]
    let mut gpu_state_store =
        if !args.lazy_merge_gpu_state || snark_proof_input.fri_proofs.len() > 1 {
            Some(zksync_airbender_cli::prover_utils::GpuSharedState::new(
                &verifier_binary,
                zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
            ))
        } else {
            None
        };
    #[cfg(feature = "gpu")]
    let mut gpu_state = gpu_state_store.as_mut();
    #[cfg(not(feature = "gpu"))]
    let mut gpu_state = None;

    let proof = merge_fris(snark_proof_input, &verifier_binary, &mut gpu_state);

    #[cfg(feature = "gpu")]
    drop(gpu_state_store);

    let final_proof = if args.skip_final_proof {
        proof
    } else {
        println!("Creating final proof before SNARKification");
        let final_proof = create_final_proofs_from_program_proof(
            proof,
            RecursionStrategy::UseReducedLog23Machine,
            cfg!(feature = "gpu"),
        );
        print_proof_info("final proof", &final_proof);
        final_proof
    };

    std::fs::create_dir_all(&args.output_dir).expect("failed to create output dir");
    let one_fri_path = Path::new(&args.output_dir).join("one_fri.tmp");
    serialize_to_file(&final_proof, &one_fri_path);
    println!("Final proof written to {one_fri_path:?}");

    if args.skip_snark {
        println!("--skip-snark set, exiting before SNARK stage");
        return;
    }

    #[cfg(feature = "gpu")]
    let late_precomputations = if !args.risc_wrapper_only && args.legacy_order {
        println!("Computing SNARK precomputations after final proof (--legacy-order)");
        let compression_vk =
            zksync_os_snark_prover::compute_compression_vk(args.binary_path.clone());
        let precomputations = zkos_wrapper::gpu::snark::gpu_create_snark_setup_data(
            &compression_vk,
            &args.trusted_setup_file,
        );
        println!("Finished computing SNARK precomputations");
        Some(precomputations)
    } else {
        None
    };

    println!("SNARKifying proof");
    #[cfg(feature = "gpu")]
    let precomputations = early_precomputations
        .as_ref()
        .or(late_precomputations.as_ref());

    match prove(
        one_fri_path.into_os_string().into_string().unwrap(),
        args.output_dir.clone(),
        Some(args.trusted_setup_file.clone()),
        args.risc_wrapper_only,
        #[cfg(feature = "gpu")]
        precomputations,
        !args.disable_zk,
    ) {
        Ok(()) if args.risc_wrapper_only => {
            println!("SUCCESS: RISC wrapper proof generated and verified")
        }
        Ok(()) => println!("SUCCESS: SNARK proof generated and verified"),
        Err(e) if args.risc_wrapper_only => {
            println!("FAILURE: failed to create RISC wrapper proof: {e:?}")
        }
        Err(e) => println!("FAILURE: failed to SNARKify proof: {e:?}"),
    }
}
