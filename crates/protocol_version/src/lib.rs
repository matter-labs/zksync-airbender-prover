use std::fmt::{self, Debug};

/// Represents a specific protocol version supported by the prover, from prover's perspective.
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
}

struct VerificationKeyHash(&'static str);
struct AirbenderVersion(&'static str);
struct ZkSyncOSVersion(&'static str);
struct ZkOsWrapperVersion(&'static str);
struct BinMd5Sum(&'static str);

/// Corresponds to server's execution_version 3 (or v1.1)
const V3: ProtocolVersion = ProtocolVersion {
    vk_hash: VerificationKeyHash(
        "0x6a4509801ec284b8921c63dc6aaba668a0d71382d87ae4095ffc2235154e9fa3",
    ),
    airbender_version: AirbenderVersion("0.5.0"),
    zksync_os_version: ZkSyncOSVersion("0.0.26"),
    zkos_wrapper: ZkOsWrapperVersion("0.5.0"),
    bin_md5sum: BinMd5Sum("fd9fd6ebfcfe7b3d1557e8a8b8563dd6"),
};

/// Represents the set of supported protocol versions by this prover implementation.
pub struct SupportedProtocolVersions {
    versions: Vec<ProtocolVersion>,
}

impl Default for SupportedProtocolVersions {
    fn default() -> Self {
        Self { versions: vec![V3] }
    }
}

impl Debug for SupportedProtocolVersions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SupportedProtocolVersions {{")?;
        for version in &self.versions {
            writeln!(f, "  vk_hash: {}", version.vk_hash.0)?;
            writeln!(f, "  airbender_version: {}", version.airbender_version.0)?;
            writeln!(f, "  zksync_os_version: {}", version.zksync_os_version.0)?;
            writeln!(f, "  zkos_wrapper: {}", version.zkos_wrapper.0)?;
            writeln!(f, "  bin_md5sum: {}", version.bin_md5sum.0)?;
            writeln!(f)?;
        }
        write!(f, "}}")
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
}
