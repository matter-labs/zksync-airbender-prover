# ZKsync OS Prover CLI

CLI tool for debugging proofs in ZKsync OS.

## Commands

### 1. Peek and Save FRI Job
```bash
cargo run --release --bin zksync-airbender-prover-cli -- \
  --url http://localhost:3124 \
  peek-and-save-fri-job \
  --block-number 123 \
  --output-dir ./jobs
```

### 2. Prove FRI Job from Peek
```bash
cargo run --release --features gpu --bin zksync-airbender-prover-cli -- \
  --url http://localhost:3124 \
  prove-fri-job-from-peek \
  --block-number 123 \
  --app-bin-path ./multiblock_batch.bin \
  --circuit-limit 10000 \
  --output-path ./proof.json
```

### 3. Prove FRI Job from File
```bash
cargo run --release --features gpu --bin zksync-airbender-prover-cli -- \
  prove-fri-job-from-file \
  --block-number 123 \
  --input-dir ./jobs \
  --app-bin-path ./multiblock_batch.bin \
  --circuit-limit 10000 \
  --output-path ./proof.json
```

## Requirements

- GPU with 24GB+ VRAM for proof generation (`--features gpu`)
- Bellman CUDA installed for GPU support

## Usage

1. **Save jobs**: `peek-and-save-fri-job` → creates `fri_job.json`
2. **Generate proofs**: `prove-fri-job-from-peek` or `prove-fri-job-from-file`
