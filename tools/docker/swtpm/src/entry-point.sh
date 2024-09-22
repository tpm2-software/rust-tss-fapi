#!/bin/sh
set -ex

swtpm_setup --tpm2 \
    --create-platform-cert \
    --tpmstate /var/lib/swtpm

swtpm socket --tpm2 \
    --server port=2321,bindaddr=0.0.0.0,disconnect \
    --ctrl type=tcp,port=2322,bindaddr=0.0.0.0 \
    --flags not-need-init \
    --tpmstate dir=/var/lib/swtpm \
    --log file=/var/log/swtpm/swtpm.log,level=20,truncate
