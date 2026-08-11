use protocol_version::{ProgramCommitment, SupportedProtocolVersions};
use std::path::Path;
use zksync_airbender_execution_utils::unrolled::UnrolledProgramProof;

/// The commitment a proof actually carries, in its final registers `18..=25`.
fn carried(proof: &UnrolledProgramProof) -> ProgramCommitment {
    let mut words = [0u32; 8];
    for (i, word) in words.iter_mut().enumerate() {
        *word = proof.register_final_values[18 + i].value;
    }
    ProgramCommitment(words)
}

/// Pins the recorded `program_commitment` against a real proof.
///
/// Checked against a proof rather than against the function that derives the commitment
/// from the binary: the previous version compared the constant to
/// `compute_program_commitment()`, but both went through `BinaryCommitment::from_base_binary`,
/// so it passed while the constant disagreed with every proof - the failure it existed to catch.
///
/// ```bash
/// FRI_PROOF_FIXTURE=/path/to/fri_proof.json \
///   cargo test -p zksync_os_fri_prover --release -- --ignored program_commitment
/// ```
#[test]
#[ignore = "needs a real FRI proof fixture; run when bumping the binary or the airbender/zkos-wrapper pins"]
fn recorded_program_commitment_matches_a_real_proof() {
    let fixture = std::env::var("FRI_PROOF_FIXTURE").expect(
        "set FRI_PROOF_FIXTURE to a serialized UnrolledProgramProof of multiblock_batch.bin",
    );
    let proof: UnrolledProgramProof = serde_json::from_reader(
        std::fs::File::open(Path::new(&fixture)).expect("cannot open FRI_PROOF_FIXTURE"),
    )
    .expect("cannot deserialize FRI_PROOF_FIXTURE as an UnrolledProgramProof");

    let carried = carried(&proof);

    let versions = SupportedProtocolVersions::default();
    let vk_hashes = versions.vk_hashes();
    assert!(!vk_hashes.is_empty(), "no supported protocol versions");
    for vk_hash in &vk_hashes {
        let recorded = versions
            .program_commitment_for(vk_hash)
            .unwrap_or_else(|| panic!("no program commitment recorded for vk_hash {vk_hash}"));
        assert_eq!(
            recorded, carried,
            "program commitment recorded for vk_hash {vk_hash} ({recorded}) does not match \
             the commitment the proof carries in registers 18..=25 ({carried})"
        );
    }
}
