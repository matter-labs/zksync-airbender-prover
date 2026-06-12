# SNARK batch 204254 repro

Run this from the repo root. This is GPU-only; the failure being investigated is
not a CPU repro.

```shell
CUDAARCHS='89;100' cargo build --release --features gpu --bin snark_repro

RUST_MIN_STACK=267108864 ./target/release/snark_repro \
  --batch-file crates/zksync_os_snark_prover/src/bin/batch_204254.json \
  --binary-path ./multiblock_batch.bin \
  --trusted-setup-file ./crs/setup_compact.key \
  --output-dir ./outputs/snark-repro-204254
```

Expected local result: the run reaches `SUCCESS: SNARK proof generated and
verified`. The production failure being checked happens earlier, during the
compression proof verification inside `zkos_wrapper::prove`.
