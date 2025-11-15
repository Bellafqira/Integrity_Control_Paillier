#!/bin/bash

LOGFILE="run_pipeline_output.log"

echo "=== Pipeline started at $(date) ===" | tee -a "$LOGFILE"

run() {
    echo "" | tee -a "$LOGFILE"
    echo "=== Running: $1 ===" | tee -a "$LOGFILE"
    bash -c "$1" 2>&1 | tee -a "$LOGFILE"
}

run "python scripts/cli.py generate-keys --key-dir 'my_keys_2048' --paillier-bits 2048"

run "python scripts/cli.py embed --in-file 'data/meshes/casting.obj' --out-file 'outputs/models/casting_signed_2048_dsb.pkl' --key-dir 'my_keys_2048' --delta 4 --quant 1000000 --sig-type dsb"

run "python scripts/cli.py embed --in-file 'data/meshes/casting.obj' --out-file 'outputs/models/casting_signed_2048_psb.pkl' --key-dir 'my_keys_2048' --delta 4 --quant 1000000 --sig-type psb"

run "python scripts/cli.py verify --in-file 'outputs/models/casting_signed_2048_psb.pkl' --out-model 'outputs/models/casting_decrypted_verified_psb.obj' --key-dir 'my_keys_2048'"

run "python scripts/cli.py verify --in-file 'outputs/models/casting_signed_2048_dsb.pkl' --out-model 'outputs/models/casting_decrypted_verified_dsb.obj' --key-dir 'my_keys_2048'"

echo "=== Pipeline finished at $(date) ===" | tee -a "$LOGFILE"
