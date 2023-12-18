#!/bin/bash
algos=("codel" "red" "taildrop")

# for algo in "${algos[@]}"
# do
#     echo "Running with algo = $algo"
#     sudo python mitigate_bufferbloat.py -a $algo
# done

sudo python mitigate_bufferbloat.py -a red

sudo python draw_mitigate.py 