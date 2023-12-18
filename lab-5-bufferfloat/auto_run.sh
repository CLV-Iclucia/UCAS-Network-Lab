#!/bin/bash
qlens=("60" "70" "80" "90" "100" "110" "120" "130" "140" "150")

for i in "${qlens[@]}"
do
    echo "Running with q = $i"
    sudo python reproduce_bufferbloat.py -q $i
    sudo python draw.py $i
done