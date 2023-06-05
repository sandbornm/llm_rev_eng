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

# Extract all strings in the binary
echo "Extracting all strings in the binary..."
strings "$binary_file" > "$output_dir/${binary_name}_strings.txt"

# Extract IP addresses and domain names from the strings file
echo "Extracting IP addresses and domain names from the strings..."
grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}|[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+" "$output_dir/${binary_name}_strings.txt" > "$output_dir/${binary_name}_ip_domains.txt"

echo "Extraction complete. Results written to $output_dir."
