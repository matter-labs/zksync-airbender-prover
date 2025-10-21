use std::fmt::Debug;
use std::hash::Hash;

#[cfg(feature = "gpu")]
use zksync_airbender_gpu_prover::circuit_type::MainCircuitType;

#[cfg(feature = "gpu")]
use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};

#[cfg(feature = "gpu")]
pub use zksync_airbender_execution_utils::execution::prover::{ExecutableBinary, ExecutionProver};

#[cfg(feature = "gpu")]
pub struct MultiBinaryProver<K: Clone + Debug + Eq + Hash> {
    execution_prover: ExecutionProver<K>,
    recursion_key: K,
}

#[cfg(feature = "gpu")]
impl<K: Clone + Debug + Eq + Hash> MultiBinaryProver<K> {
    pub fn new(
        max_concurrent_batches: usize,
        main_binaries: Vec<(K, MainCircuitType, Vec<u32>)>,
        recursion_circuit_type: MainCircuitType,
        recursion_key: K,
    ) -> Self {
        // Validate recursion circuit type
        assert!(
            recursion_circuit_type == MainCircuitType::ReducedRiscVMachine
                || recursion_circuit_type == MainCircuitType::ReducedRiscVLog23Machine,
            "Recursion circuit type must be ReducedRiscVMachine or ReducedRiscVLog23Machine"
        );

        // Convert main binaries to ExecutableBinary
        let mut all_binaries: Vec<ExecutableBinary<K, Vec<u32>>> = main_binaries
            .into_iter()
            .map(|(key, circuit_type, bytecode)| ExecutableBinary {
                key,
                circuit_type,
                bytecode,
            })
            .collect();

        // Add recursion binary (universal circuit verifier)
        let recursion_binary = ExecutableBinary {
            key: recursion_key.clone(),
            circuit_type: recursion_circuit_type,
            bytecode: get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER),
        };
        all_binaries.push(recursion_binary);

        let execution_prover = ExecutionProver::new(max_concurrent_batches, all_binaries);

        Self {
            execution_prover,
            recursion_key,
        }
    }

    pub fn execution_prover(&self) -> &ExecutionProver<K> {
        &self.execution_prover
    }

    pub fn execution_prover_mut(&mut self) -> &mut ExecutionProver<K> {
        &mut self.execution_prover
    }

    pub fn recursion_key(&self) -> &K {
        &self.recursion_key
    }
}

/// Non-GPU version of MultiBinaryProver (placeholder for compatibility)
#[cfg(not(feature = "gpu"))]
pub struct MultiBinaryProver<K: Clone + Debug + Eq + Hash> {
    _phantom: std::marker::PhantomData<K>,
}

#[cfg(not(feature = "gpu"))]
impl<K: Clone + Debug + Eq + Hash> MultiBinaryProver<K> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<K: Clone + Debug + Eq + Hash> Default for MultiBinaryProver<K> {
    fn default() -> Self {
        Self::new()
    }
}
