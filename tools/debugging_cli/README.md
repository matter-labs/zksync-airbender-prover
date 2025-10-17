# ZKsync OS Prover Debugging CLI

CLI tool for debugging FRI and SNARK proofs in ZKsync OS.

## FRI Commands

### 1. Peek and Save FRI Job
```bash
cargo run --release --bin prover-debugging-cli -- \
  peek-and-save-fri-job \
  --url http://localhost:3124 \
  --block-number 123 \
  --output-dir ./jobs
```

### 2. Prove FRI Job from Peek
```bash
cargo run --release --features gpu --bin prover-debugging-cli -- \
  prove-fri-job-from-peek \
  --url http://localhost:3124 \
  --block-number 123 \
  --app-bin-path ./multiblock_batch.bin \
  --circuit-limit 10000 \
  --output-path ./proof.json
```

### 3. Prove FRI Job from File
```bash
cargo run --release --features gpu --bin prover-debugging-cli -- \
  prove-fri-job-from-file \
  --block-number 123 \
  --input-dir ./jobs \
  --app-bin-path ./multiblock_batch.bin \
  --circuit-limit 10000 \
  --output-path ./proof.json
```

## SNARK Commands

### 4. Peek and Save SNARK Job
```bash
cargo run --release --bin prover-debugging-cli -- \
  peek-and-save-snark-job \
  --url http://localhost:3124 \
  --from-block 100 \
  --to-block 105 \
  --output-dir ./snark_jobs
```

### 5. Prove SNARK Job from Peek
```bash
cargo run --release --features gpu --bin prover-debugging-cli -- \
  prove-snark-job-from-peek \
  --url http://localhost:3124 \
  --from-block 100 \
  --to-block 105 \
  --trusted-setup-path ./setup_compact.key \
  --output-dir ./outputs
```

### 6. Prove SNARK Job from File
```bash
cargo run --release --features gpu --bin prover-debugging-cli -- \
  prove-snark-job-from-file \
  --input-dir ./snark_jobs \
  --trusted-setup-path ./setup_compact.key \
  --output-dir ./outputs
```

## SNARK Prover Stages

The SNARK prover has three internal stages that can be run independently or in any combination.
- `merge_fris`
- `final proof`
- `snarkifying`
You can specify stages you want to run by setting flags. 
For example: `--merge-fris false --final-proof true --snarkifying false`. 
By default all stages are run.
All intermediate files are saved in `--output-dir`.
