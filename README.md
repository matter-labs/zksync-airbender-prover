# ZKsync OS: Airbender Prover
This repo contains the Prover Service implementation for ZKsync OS Airbender prover.

## Overview

This repo contains 3 crates:
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

Before starting, please download the trusted setup file (see info in crs/README.md).



Sample usage for commands.

**This command currently requires a GPU (at least 24GB of VRAM)**

```bash
# start FRI prover
cargo run --release --features gpu --bin zksync_os_fri_prover -- --base-url http://localhost:3124 --app-bin-path ./multiblock_batch.bin
```
Specify optional `--iterations` arguement to run FRI prover N times and then exit.

**This command currently requires around 140 GB of RAM - and GPU**

```bash
# optional - increase stack size to 300M (TODO: check if this could be lower)
ulimit -s 300000

# start SNARK prover
RUST_MIN_STACK=267108864 cargo run --release --features gpu --bin zksync_os_snark_prover -- run-prover --sequencer-url http://localhost:3124 --binary-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs
```

This one is only needed if you want to manually upload.

```bash
# submit a SNARK proof manually to sequencer
cargo run --release --bin sequencer_proof_client -- submit-snark --from-block-number 1 --to-block-number 10 --path ./outputs/snark_proof.json --url http://localhost:3124
```

## Development / WIP

* Add information on how to setup GPU for snark wraper


## FAQ

If you get the error like `cargo::rustc-check-cfg=cfg(no_cuda)` during compilation, you might have to install
Bellman Cuda (see instructions below).


## Installing bellman-cuda


```shell
git clone https://github.com/matter-labs/era-bellman-cuda.git --branch main bellman-cuda && \
cmake -Bbellman-cuda/build -Sbellman-cuda/ -DCMAKE_BUILD_TYPE=Release && \
cmake --build bellman-cuda/build/
```

And then:

```shell
export BELLMAN_CUDA_DIR=...
```



## Policies

- [Security policy](SECURITY.md)
- [Contribution policy](CONTRIBUTING.md)

## License

ZKsync OS repositories are distributed under the terms of either

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/blog/license/mit/>)

at your option.

## Official Links

- [Website](https://zksync.io/)
- [GitHub](https://github.com/matter-labs)
- [ZK Credo](https://github.com/zksync/credo)
- [Twitter](https://twitter.com/zksync)
- [Twitter for Developers](https://twitter.com/zkSyncDevs)
- [Discord](https://join.zksync.dev/)
- [Mirror](https://zksync.mirror.xyz/)
- [Youtube](https://www.youtube.com/@zkSync-era)