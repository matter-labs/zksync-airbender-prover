use std::fmt::{self, Debug};

struct ProtocolVersion {
    pub vk_hash: VerificationKeyHash,
    pub airbender_version: AirbenderVersion,
    pub zksync_os_version: ZkSyncOSVersion,
    pub zkos_wrapper: ZkOsWrapperVersion,
    pub bin_md5sum: BinMd5sum,
}

struct VerificationKeyHash(&'static str);
struct AirbenderVersion(&'static str);
struct ZkSyncOSVersion(&'static str);
struct ZkOsWrapperVersion(&'static str);
struct BinMd5sum(&'static str);

const V3: ProtocolVersion = ProtocolVersion {
    vk_hash: VerificationKeyHash(
        "0x6a4509801ec284b8921c63dc6aaba668a0d71382d87ae4095ffc2235154e9fa3",
    ),
    airbender_version: AirbenderVersion("0.5.0"),
    zksync_os_version: ZkSyncOSVersion("0.0.26"),
    zkos_wrapper: ZkOsWrapperVersion("0.5.0"),
    bin_md5sum: BinMd5sum("fd9fd6ebfcfe7b3d1557e8a8b8563dd6"),
};

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
    pub fn contains(&self, vk_hash: &str) -> bool {
        for version in &self.versions {
            if version.vk_hash.0 == vk_hash {
                return true;
            }
        }
        false
    }

    pub fn vk_hashes(&self) -> Vec<String> {
        self.versions
            .iter()
            .map(|version| version.vk_hash.0.to_string())
            .collect()
    }
}
