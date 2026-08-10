use protocol_version::SupportedProtocolVersions;
use std::path::Path;

/// Pins the recorded `program_commitment` values to the repo's `multiblock_batch.bin`.
/// Run when bumping the binary or the airbender/zkos-wrapper pins:
///
/// ```bash
/// cargo test -p zksync_os_fri_prover --release -- --ignored program_commitment
/// ```
#[test]
#[ignore = "recomputes program setup caps (minutes in debug); run in release when bumping the binary or pins"]
fn recorded_program_commitment_matches_repo_binary() {
    let binary_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../multiblock_batch.bin");
    let computed = zksync_os_fri_prover::compute_program_commitment(&binary_path)
        .expect("failed to compute program commitment");

    let versions = SupportedProtocolVersions::default();
    let vk_hashes = versions.vk_hashes();
    assert!(!vk_hashes.is_empty(), "no supported protocol versions");
    for vk_hash in &vk_hashes {
        let recorded = versions
            .program_commitment_for(vk_hash)
            .unwrap_or_else(|| panic!("no program commitment recorded for vk_hash {vk_hash}"));
        assert_eq!(
            recorded, computed,
            "program commitment recorded for vk_hash {vk_hash} ({recorded}) does not match \
             the repo's multiblock_batch.bin ({computed})"
        );
    }
}
