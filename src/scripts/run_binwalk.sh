#!/bin/bash

# Check if the input file is provided
if [ $# -eq 0 ]; then
  echo "Usage: ./run_binwalk.sh <input_file>"
  exit 1
fi

input_file=$1
output_file="../../data/$(basename "${input_file%.*}")/binwalk_analysis.csv"

# verbose, csv file, signature, opcode detection, scan extracted files, 
binwalk -vcBAM "$input_file" > "$output_file"

echo "Binwalk analysis completed. Results saved to $output_file"
