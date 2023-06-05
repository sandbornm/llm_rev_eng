#!/bin/bash

binary_file=$1

# Check if a binary file is provided
if [ -z "$binary_file" ]; then
  echo "Usage: $0 <binary_file>"
  exit 1
fi

# Get the binary name without the extension
binary_name=$(basename "$binary_file" | cut -d. -f1)

# Set the output directory
output_dir="../../data/$binary_name"

# Create the output directory if it doesn't exist
mkdir -p "$output_dir"

# run file command on the binary
echo "Running file command on the binary..."
file "$binary_file" > "$output_dir/${binary_name}_file.txt"

# run checksec
echo "Running checksec..."
checksec "$binary_file" > "$output_dir/${binary_name}_checksec.txt"
