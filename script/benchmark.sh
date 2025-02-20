#!/bin/bash

echo $1 >> benchmark.txt

for n in 16 32 64 128 256 512 1024 2048 4096; do
    echo "Running script with n=$n"
    echo -n "$n " >> benchmark.txt
    cargo run --bin $1 --release -- --execute --n $n | grep "Number of cycles" | awk '{print $4}' >> benchmark.txt
done