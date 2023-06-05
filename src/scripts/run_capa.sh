#!/bin/bash

binary_file=$1

# Check if a binary file is provided
if [ -z "$binary_file" ]; then
  echo "Usage: $0 <binary_file>"
  exit 1
fi

# Retrieve the name of the binary file
binary_name=$(basename "$binary_file")

# Set the output directory
output_dir="../../data/$binary_name"

# Create the output directory if it doesn't exist
mkdir -p "$output_dir"

# Detect the operating system
uname_output=$(uname -a)
if echo "$uname_output" | grep -q "Darwin"; then
  capa_binary="capa_macos"
elif echo "$uname_output" | grep -q "Linux"; then
  capa_binary="capa_linux"
else
  echo "Unsupported operating system."
  exit 1
fi

# Run Capa on the binary using the appropriate binary and write the output to the file
capa_cmd="../bin/$capa_binary $binary_file"
output_file="$output_dir/${binary_name%.*}_capa_report.txt"
eval "$capa_cmd" > "$output_file"

echo "Capa analysis complete. Results written to $output_file."
