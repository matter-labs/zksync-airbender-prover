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
    /// The SNARK wrapper bakes it into the VK (registers 18..=25 == aux_params, via
    /// `check_aux_params`), so `vk_hash` alone identifies the app program again; this field
    /// is the plaintext of that binding, used to reject wrong-program FRI proofs up front
    /// and to re-derive/verify the VK. `None` pre-V8 (the VK already covered the binary).
    program_commitment: Option<ProgramCommitment>,
    /// FRI proving security level the version's constants were generated at (see
    /// [`SecurityLevel`]). `None` pre-V8: those versions predate the level being recorded
    /// and proved at airbender's then-default.
    security_level: Option<SecurityLevel>,
}

/// FRI proving security level of a protocol version. The level selects the recursion
/// verifier binaries, so `program_commitment` and `vk_hash` are specific to it: the
/// values for the same app binary at another level differ and are not interchangeable,
/// which is why the level is recorded here, next to the constants it invalidates.
///
/// Mirrors airbender's `SecurityLevel` as plain data (this crate has no dependencies);
/// the prover crates map it to airbender's type where they configure proving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 80-bit security.
    Security80,
    /// 100-bit security.
    Security100,
}

/// Blake2s recursion-chain commitment binding a protocol version to its app program: the
/// base program's `end_params` folded with the unrolled recursion verifier's — the value
/// proofs expose in final registers 18..=25. The SNARK wrapper constrains those registers
/// to this value in-circuit (`check_aux_params`), so the app program is bound through the
/// VK rather than carried in the SNARK public input. See
/// `zksync_os_fri_prover::compute_program_commitment`.
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
    security_level: None,
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
    security_level: None,
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
    security_level: None,
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
    security_level: None,
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
    security_level: None,
};

/// Corresponds to server's proving version V10 (protocol v33.0, zksync-os 0.5.3-private
/// native batch prover); the `V8` name here predates the server-side renumbering.
const V8: ProtocolVersion = ProtocolVersion {
    // Keccak256 of the phase-3 SNARK VK (`generate-vk --check-aux-params`), so it binds the
    // app binary and the program commitment below. Regenerate when the binary, the level, or the
    // pins change - a moved commitment moves this too.
    // NOTE: not yet registered on L1.
    vk_hash: VerificationKeyHash(
        "0x29651d5f044e1671ff820f85018ed87b26f57402222eb31dd453206e2379bc9c",
    ),
    airbender_version: AirbenderVersion("di/fix/87680-fri-fix-dev @ af42767a"),
    zksync_os_version: ZkSyncOSVersion("v0.5.3-private"),
    zkos_wrapper: ZkOsWrapperVersion("di/fix/87680-fri-fix-dev @ 301e380e"),
    // zksync-os v0.5.3-private release tag (@ c8709ca5), built reproducibly; sha256
    // 5743a82a713be186bca21f7fa2f4a84b59d964f23781f87d149471dee975b486, byte-identical to the
    // asset published on that release. The tag changes the L1-transaction flow (prewarm is
    // allowed to fail), so it is a new binary and every constant here moved with it.
    bin_md5sum: BinMd5Sum("802412374f7aa2cf506a548c25d07e8a"),
    // base -> unrolled -> unified: what real proofs expose in registers 18..=25.
    // Specific to the 100-bit level below, like the vk_hash above.
    // From `wrapper compute-aux-params` at the pins below.
    program_commitment: Some(ProgramCommitment([
        0x6d20dde5, 0x63e39422, 0x96587bd3, 0xce0ae20c, 0x8d8c0add, 0xeec167d8, 0x5c327b26,
        0xf2ee90d7,
    ])),
    security_level: Some(SecurityLevel::Security100),
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

    /// The security level the prover process proves at: the one level shared by every
    /// supported version that records one, `None` if no version records a level.
    ///
    /// The level is fixed per process — the provers and the combiner are configured with
    /// it at construction, before any job (and its vk_hash) is known — so a version set
    /// mixing levels cannot be served by one process. This panics on such a set rather
    /// than silently picking a level; the set is a compile-time constant, so the panic
    /// marks a broken edit of this file, not a runtime condition.
    pub fn proving_security_level(&self) -> Option<SecurityLevel> {
        let mut levels = self.versions.iter().filter_map(|v| v.security_level);
        let first = levels.next()?;
        assert!(
            levels.all(|level| level == first),
            "supported protocol versions record different proving security levels; \
             one prover process cannot serve them all"
        );
        Some(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The getter panics on a mixed-level version set; catch that here instead of at
    /// prover startup. Pinning the value also guards the V8+ constants against a level
    /// edit that forgets to regenerate `program_commitment` and `vk_hash` with it.
    #[test]
    fn default_versions_share_one_proving_security_level() {
        assert_eq!(
            SupportedProtocolVersions::default().proving_security_level(),
            Some(SecurityLevel::Security100)
        );
    }
}
