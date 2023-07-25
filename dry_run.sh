# !/bin/bash
# This script is a `dry_run', i.e., not actually running any of the commands
# under NPF, but only get the commands executed by it, and later running it
# by ourselves
# Currently in my view, NPF starts off great, aiming to provide a one-liner
# to conduct experiments and draw graphs, but its so hard to use, read and
# customize, making it still some distance to practical

# Command from
# https://github.com/hamidgh09/Reframer/blob/main/experiments/Reframer/Makefile#L21

# running instead of comparing
./npf-run.py \
        --test chain-pcap-new.npf \
        --cluster gen=localhost \
        --tags promisc reframer dutmid fw nat fc router reclass\
        --config n_runs=1 \
        --variables SFDELAY=64 \
        --show-full --show-cmd
