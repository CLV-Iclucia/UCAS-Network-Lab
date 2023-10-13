#!/bin/bash

if [ $# -lt 1 ]; then
	echo "#(nodes) is required.";
	exit 1;
fi

for i in `seq 1 $1`; do
	echo "NODE b$i dumps:";
	# cat b$i-output.txt | grep -v "DEBUG";
	cat b$i-output.txt | grep "INFO";
	echo "";
done

echo "===============================";
echo "reference output";
for i in `seq 1 $1`; do
	echo "NODE b$i dumps:";
	# cat b$i-output.txt | grep -v "DEBUG";
	cat b$i-output-ref.txt | grep "INFO";
	echo "";
done

# compare the output
for i in `seq 1 $1`; do
	echo "diffing b$i-output.txt and b$i-output-ref.txt";
	diff <(cat b$i-output.txt | grep "INFO") <(cat b$i-output-ref.txt | grep "INFO");
done