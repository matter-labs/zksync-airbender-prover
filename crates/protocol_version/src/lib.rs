// NOTE: Usage of allow(dead_code) is intentional here, as fields are used in the Debug macro,
// but the compiler doesn't seem to be able to infer it directly.

/// Represents a specific protocol version supported by the prover, from prover's perspective.
#[derive(Debug)]
#[allow(dead_code)]
struct ProtocolVersion {
    /// verification key hash identifying this protocol version
    vk_hash: VerificationKeyHash,
    /// version of airbender used
    /// NOTE: this can be inferred from vk_hash, but we keep it here for easier cross-checking
    airbender_version: AirbenderVersion,
    /// version of zksync os used
    /// NOTE: this can be inferred from vk_hash, but we keep it here for easier cross-checking
    zksync_os_version: ZkSyncOSVersion,
    /// version of zkos wrapper used
    /// NOTE: this can be inferred from vk_hash, but we keep it here for easier cross-checking
    zkos_wrapper: ZkOsWrapperVersion,
    /// md5sum of the prover binary used for proving
    /// NOTE: in the future we may want to support multiple binaries (such as debug mode)
    /// NOTE2: this can be inferred from zksync_os_version, but we keep it here for easier cross-checking
    bin_md5sum: BinMd5Sum,
    /// Chain commitment of the app program this version proves (see [`ProgramCommitment`]).
    /// Since V8 the SNARK VK is app-independent, so the (vk_hash, program_commitment)
    /// pair is what identifies a version. `None` pre-V8 (VK covered the binary).
    program_commitment: Option<ProgramCommitment>,
}

/// Blake2s recursion-chain commitment binding a protocol version to its app program:
/// the base program's `end_params` folded with the unrolled recursion verifier's — the
/// value proofs expose in final registers 18..=25 and the settlement side checks the
/// SNARK public input against. See `zksync_os_fri_prover::compute_program_commitment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramCommitment(pub [u32; 8]);

impl std::fmt::Display for ProgramCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for word in self.0 {
            write!(f, "{word:08x}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct VerificationKeyHash(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct AirbenderVersion(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct ZkSyncOSVersion(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct ZkOsWrapperVersion(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct BinMd5Sum(&'static str);

/// Corresponds to server's execution_version 3 (or v1.1)
#[allow(dead_code)]
const V3: ProtocolVersion = ProtocolVersion {
    vk_hash: VerificationKeyHash(
        "0x6a4509801ec284b8921c63dc6aaba668a0d71382d87ae4095ffc2235154e9fa3",
    ),
    airbender_version: AirbenderVersion("v0.5.0"),
    zksync_os_version: ZkSyncOSVersion("v0.0.26"),
    zkos_wrapper: ZkOsWrapperVersion("v0.5.0"),
    bin_md5sum: BinMd5Sum("fd9fd6ebfcfe7b3d1557e8a8b8563dd6"),
    program_commitment: None,
};

/// Corresponds to server's execution_version 4 (or v1.2)
#[allow(dead_code)]
const V4: ProtocolVersion = ProtocolVersion {
    vk_hash: VerificationKeyHash(
        "0xa385a997a63cc78e724451dca8b044b5ef29fcdc9d8b6ced33d9f58de531faa5",
    ),
    airbender_version: AirbenderVersion("v0.5.1"),
    zksync_os_version: ZkSyncOSVersion("v0.1.0"),
    zkos_wrapper: ZkOsWrapperVersion("v0.5.3"),
    bin_md5sum: BinMd5Sum("a3fffd4f2e14e7171c2207e470316e5f"),
    program_commitment: None,
};

/// Corresponds to server's execution_version 5 (or v1.3)
#[allow(dead_code)]
const V5: ProtocolVersion = ProtocolVersion {
    vk_hash: VerificationKeyHash(
        "0x996b02b1d0420e997b4dc0d629a3a1bba93ed3185ac463f17b02ff83be139581",
    ),
    airbender_version: AirbenderVersion("v0.5.1"),
    zksync_os_version: ZkSyncOSVersion("v0.2.4"),
    zkos_wrapper: ZkOsWrapperVersion("v0.5.3"),
    bin_md5sum: BinMd5Sum("a2421384eb817ba2649f1438dc321d54"),
    program_commitment: None,
};

/// Corresponds to server's execution_version 6 (or v1.3.1)
#[allow(dead_code)]
const V6: ProtocolVersion = ProtocolVersion {
    vk_hash: VerificationKeyHash(
        "0x124ebcd537a1e1c152774dd18f67660e35625bba0b669bf3b4836d636b105337",
    ),
    airbender_version: AirbenderVersion("v0.5.2"),
    zksync_os_version: ZkSyncOSVersion("v0.2.5"),
    zkos_wrapper: ZkOsWrapperVersion("v0.5.4"),
    bin_md5sum: BinMd5Sum("e77ced130723f3e52099658d589a8454"),
    program_commitment: None,
};

/// Corresponds to server's execution_version 7
#[allow(dead_code)]
const V7: ProtocolVersion = ProtocolVersion {
    vk_hash: VerificationKeyHash(
        "0x23156cf220288cd1e436dccfc09aa4883ea8288da61aa69e2c7251b0c0c44ccd",
    ),
    airbender_version: AirbenderVersion("v0.5.2"),
    zksync_os_version: ZkSyncOSVersion("v0.3.0"),
    zkos_wrapper: ZkOsWrapperVersion("v0.5.5"),
    bin_md5sum: BinMd5Sum("99d1618fdf63d80c4a6ed41cf21ed4d6"),
    program_commitment: None,
};

/// Corresponds to server's execution_version 8 (protocol v32.0, zksync-os 0.4.0 native batch prover)
const V8: ProtocolVersion = ProtocolVersion {
    vk_hash: VerificationKeyHash(
        "0x3e7784b0fdb09035a677ae80568d34fdb1f1ec6ac65bba5192cd977a4f0e7609",
    ),
    airbender_version: AirbenderVersion("v0.6.0-rc.1"),
    zksync_os_version: ZkSyncOSVersion("v0.4.0"),
    zkos_wrapper: ZkOsWrapperVersion("v0.6.0-rc.1"),
    bin_md5sum: BinMd5Sum("3e19df8c36564939950e0a079061ad1b"),
    program_commitment: Some(ProgramCommitment([
        0x925e5e40, 0xf526b71c, 0x1ee4f8b1, 0xea01856f, 0xf2f836fb, 0x19b96ed6, 0xb36a9404,
        0x248d5773,
    ])),
};

/// Represents the set of supported protocol versions by this prover implementation.
#[derive(Debug)]
pub struct SupportedProtocolVersions {
    versions: Vec<ProtocolVersion>,
}

impl Default for SupportedProtocolVersions {
    fn default() -> Self {
        Self { versions: vec![V8] }
    }
}

impl SupportedProtocolVersions {
    /// Checks if the given VK hash is supported.
    pub fn contains(&self, vk_hash: &str) -> bool {
        self.versions.iter().any(|v| v.vk_hash.0 == vk_hash)
    }

    /// Returns the list of supported VK hashes as strings.
    pub fn vk_hashes(&self) -> Vec<String> {
        self.versions
            .iter()
            .map(|version| version.vk_hash.0.to_string())
            .collect()
    }

    /// The app-program commitment recorded for the version with this VK hash;
    /// `None` if the version is unsupported or pre-V8.
    pub fn program_commitment_for(&self, vk_hash: &str) -> Option<ProgramCommitment> {
        self.versions
            .iter()
            .find(|v| v.vk_hash.0 == vk_hash)
            .and_then(|v| v.program_commitment)
    }

    /// Checks whether some supported version proves the app program with this commitment.
    pub fn supports_program(&self, commitment: &ProgramCommitment) -> bool {
        self.versions
            .iter()
            .any(|v| v.program_commitment.as_ref() == Some(commitment))
    }
}
