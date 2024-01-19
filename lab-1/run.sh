#!/bin/bash

sizes=("1M" "10M" "100M")
bandwidths=("10" "50" "100" "500" "1000")
delays=("100ms")

# create a file to contain all the results
touch result.txt
# for all the combinations of sizes, bandwidths and delays, run fct_exp.py
for size in "${sizes[@]}"
do
    for bandwidth in "${bandwidths[@]}"
    do
        for delay in "${delays[@]}"
        do
            # set up a number to accumulate the summation of the time
            sum=0
            # repeating for 5 times
            for i in {1..5}
            do
                #echo the current combination
                echo "size: $size, bandwidth: $bandwidth, delay: $delay"
                sudo python fct_exp.py $size $bandwidth $delay
                output="result_"$size"_"$bandwidth"_"$delay".txt"
                result_time=$(grep -oE '=(.*)s' $output | sed 's/=\(.*\)s/\1/')
                echo $result_time
                # add the result_time to sum
                sum=$(echo $sum + $result_time | bc)
                # remove the file with name containing "dat"
                sudo rm *dat*
            done
            # calculate the average time
            avg=$(echo $sum / 5 | bc -l)
            # append arguments and avg to the result file directly without other information
            echo $size $bandwidth $delay $avg >> result.txt
            # remove output file
        done
    done
done