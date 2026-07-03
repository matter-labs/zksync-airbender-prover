//! E2E validation harness for generated verification keys.
//!
//! Loads proofs/VKs from JSON (this repo's format) or bincode-v2-standard
//! (zkos-wrapper's testing_data fixtures), sniffing the format per file.
//!
//!   vk_e2e hash <snark_vk>
//!   vk_e2e verify <risc-wrapper|compression|snark> <proof> <vk>
//!   vk_e2e vk-cross <risc-wrapper|compression|snark> <vk_a> <vk_b>
//!   vk_e2e prove-all <unrolled_proof> <bin|-> <text|-> <crs> <output_dir>

use std::path::PathBuf;

use zkos_wrapper::{
    calculate_verification_key_hash, verify_compression_proof, verify_risc_wrapper_proof,
    verify_snark_wrapper_proof, CompressionProof, CompressionVK, RiscWrapperProof, RiscWrapperVK,
    SnarkWrapper, SnarkWrapperConfig, SnarkWrapperProof, SnarkWrapperVK,
};
use zksync_airbender_execution_utils::unrolled::UnrolledProgramProof;
use zksync_os_snark_prover::init_tracing;

fn load<T: serde::de::DeserializeOwned>(path: &str) -> anyhow::Result<T> {
    let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    let first = bytes
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .copied()
        .unwrap_or(0);
    if first == b'{' || first == b'[' {
        serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!("json-parsing {path}: {e}"))
    } else {
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| anyhow::anyhow!("bincode-parsing {path}: {e}"))
    }
}

fn save_json<T: serde::Serialize>(value: &T, dir: &str, name: &str) -> anyhow::Result<()> {
    let path = PathBuf::from(dir).join(name);
    serde_json::to_writer_pretty(std::fs::File::create(&path)?, value)?;
    tracing::info!("Saved {}", path.display());
    Ok(())
}

fn json_eq<T: serde::Serialize>(a: &T, b: &T) -> anyhow::Result<bool> {
    Ok(serde_json::to_value(a)? == serde_json::to_value(b)?)
}

fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    match (cmd, args.len()) {
        ("hash", 2) => {
            let vk: SnarkWrapperVK = load(&args[1])?;
            println!("VK_HASH: {:?}", calculate_verification_key_hash(vk));
            Ok(())
        }
        ("verify", 4) => {
            let valid = match args[1].as_str() {
                "risc-wrapper" => {
                    let proof: RiscWrapperProof = load(&args[2])?;
                    let vk: RiscWrapperVK = load(&args[3])?;
                    verify_risc_wrapper_proof(&proof, &vk)
                }
                "compression" => {
                    let proof: CompressionProof = load(&args[2])?;
                    let vk: CompressionVK = load(&args[3])?;
                    verify_compression_proof(&proof, &vk)
                }
                "snark" => {
                    let proof: SnarkWrapperProof = load(&args[2])?;
                    let vk: SnarkWrapperVK = load(&args[3])?;
                    verify_snark_wrapper_proof(&proof, &vk)
                }
                other => anyhow::bail!("unknown stage {other}"),
            };
            println!("VERIFY_RESULT: {}", if valid { "VALID" } else { "INVALID" });
            if !valid {
                std::process::exit(1);
            }
            Ok(())
        }
        ("vk-cross", 4) => {
            let equal = match args[1].as_str() {
                "risc-wrapper" => {
                    json_eq(&load::<RiscWrapperVK>(&args[2])?, &load(&args[3])?)?
                }
                "compression" => {
                    json_eq(&load::<CompressionVK>(&args[2])?, &load(&args[3])?)?
                }
                "snark" => json_eq(&load::<SnarkWrapperVK>(&args[2])?, &load(&args[3])?)?,
                other => anyhow::bail!("unknown stage {other}"),
            };
            println!("VK_EQUAL: {equal}");
            Ok(())
        }
        ("prove-all", 6) => {
            let proof: UnrolledProgramProof = load(&args[1])?;
            let opt = |s: &str| (s != "-").then(|| PathBuf::from(s));
            let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
                bin: opt(&args[2]),
                text: opt(&args[3]),
                trusted_setup: Some(PathBuf::from(&args[4])),
                threads: None,
                risc_wrapper_vk: None,
                compression_vk: None,
                snark_vk: None,
            })?;
            let out = &args[5];
            std::fs::create_dir_all(out)?;

            let risc_wrapper_proof = wrapper.prove_risc_wrapper(proof)?;
            save_json(&risc_wrapper_proof, out, "risc_wrapper_proof.json")?;
            save_json(wrapper.risc_wrapper_vk()?, out, "risc_wrapper_vk.json")?;

            let compression_proof = wrapper.prove_compression(risc_wrapper_proof)?;
            save_json(&compression_proof, out, "compression_proof.json")?;
            save_json(wrapper.compression_vk()?, out, "compression_vk.json")?;

            let snark_proof = wrapper.prove_snark(compression_proof, false)?;
            save_json(&snark_proof, out, "snark_proof.json")?;
            save_json(wrapper.snark_vk()?, out, "snark_vk.json")?;

            let hash = calculate_verification_key_hash(wrapper.snark_vk()?.clone());
            println!("VK_HASH: {hash:?}");
            println!("PROVE_ALL: DONE");
            Ok(())
        }
        ("prove-compression", 4) => {
            let proof: RiscWrapperProof = load(&args[1])?;
            let vk: RiscWrapperVK = load(&args[2])?;
            let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
                bin: None,
                text: None,
                trusted_setup: None,
                threads: None,
                risc_wrapper_vk: Some(vk),
                compression_vk: None,
                snark_vk: None,
            })?;
            let out = &args[3];
            std::fs::create_dir_all(out)?;
            let compression_proof = wrapper.prove_compression(proof)?;
            save_json(&compression_proof, out, "compression_proof.json")?;
            save_json(wrapper.compression_vk()?, out, "compression_vk.json")?;
            println!("PROVE_COMPRESSION: DONE");
            Ok(())
        }
        ("prove-snark", 5) => {
            let proof: CompressionProof = load(&args[1])?;
            let vk: CompressionVK = load(&args[2])?;
            let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
                bin: None,
                text: None,
                trusted_setup: Some(PathBuf::from(&args[3])),
                threads: None,
                risc_wrapper_vk: None,
                compression_vk: Some(vk),
                snark_vk: None,
            })?;
            let out = &args[4];
            std::fs::create_dir_all(out)?;
            let snark_proof = wrapper.prove_snark(proof, false)?;
            save_json(&snark_proof, out, "snark_proof.json")?;
            save_json(wrapper.snark_vk()?, out, "snark_vk.json")?;
            let hash = calculate_verification_key_hash(wrapper.snark_vk()?.clone());
            println!("VK_HASH: {hash:?}");
            println!("PROVE_SNARK: DONE");
            Ok(())
        }
        _ => anyhow::bail!(
            "usage: hash <vk> | verify <stage> <proof> <vk> | vk-cross <stage> <a> <b> | prove-all <proof> <bin|-> <text|-> <crs> <outdir> | prove-compression <proof> <vk> <outdir> | prove-snark <proof> <vk> <crs> <outdir>"
        ),
    }
}

fn main() -> anyhow::Result<()> {
    init_tracing();
    // Circuit synthesis needs a large stack; the main thread's is fixed by the OS,
    // so do all work on a spawned thread (same workaround as run-prover's tokio config).
    let stack_size = std::env::var("RUST_MIN_STACK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
        .max(256 * 1024 * 1024);
    std::thread::Builder::new()
        .stack_size(stack_size)
        .spawn(run)?
        .join()
        .map_err(|e| anyhow::anyhow!("worker thread panicked: {e:?}"))?
}
