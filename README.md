# zksync-airbender-prover
Prover Service implementation for ZKsync Airbender (zksync-os)

## Overview

Repo contains 3 crates:
- sequencer_proof_client
- zksync_os_fri_prover
- zksync_os_snark_prover

### Sequencer Proof Client

Small HTTP wrapper around the Sequencer Prover API. 
Apart from providing lib to use in provers, it also has a binary that acts as a CLI.
Useful for troubleshooting (i.e. manually pushing a SNARK proof to sequencer, instead of running the entire sequencer).

### ZKsync OS FRI Prover

The FRI prover for ZKsync OS. Retrieves proof input, proves a batch (which is a set of blocks) and submits it back to sequencer.
There's no state persisted in between.

### ZKsync OS SNARK Prover

SNARKs the final proof. Gets a set of continuous FRIs from sequencer, merges them into a single FRI, creates a FINAL proof out of it and then SNARKs it.

### Usage


Before starting, make sure that your **sequencer** has fake proofs disabled:

```
prover_api_fake_fri_provers_enabled=false prover_api_fake_snark_provers_enabled=false
```


Sample usage for commands.

**This command currently requires a GPU (at least 24GB of VRAM)**

```bash
# start FRI prover
cargo run --release --features gpu --bin zksync_os_fri_prover -- --base-url http://localhost:3124 --app-bin-path ./multiblock_batch.bin
```


**This command currently requires around 140 GB of RAM - and GPU**

```bash
# start SNARK prover
cargo run --release --features gpu --bin zksync_os_snark_prover -- run-prover --sequencer-url http://localhost:3124 --binary-path ./multiblock_batch.bin --output-dir ./outputs
```

This one is only needed if you want to manually upload.

```bash
# submit a SNARK proof manually to sequencer
cargo run --release --bin sequencer_proof_client -- submit-snark --from-block-number 1 --to-block-number 10 --path ./outputs/snark_proof.json --url http://localhost:3124
```

## Development

Currently in WIP mode, expect changes.