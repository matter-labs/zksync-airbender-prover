#!/bin/sh

ulimit -s 300000
exec /usr/bin/zksync_os_snark_prover "$@"
