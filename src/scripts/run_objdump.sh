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

# Extract disassembly using "objdump" command
echo "Extracting disassembly using 'objdump'..."
objdump -d "$binary_file" > "$output_dir/${binary_name}_disassembly.txt"

# Extract function names using "objdump" command
echo "Extracting function names using 'objdump'..."
objdump -t "$binary_file" > "$output_dir/${binary_name}_function_names.txt"

# Extract sections information using "objdump" command
echo "Extracting sections information using 'objdump'..."
objdump -h "$binary_file" > "$output_dir/${binary_name}_sections.txt"

# Extract dynamic symbols using "objdump" command
echo "Extracting dynamic symbols using 'objdump'..."
objdump -T "$binary_file" > "$output_dir/${binary_name}_dynamic_symbols.txt"

# Extract relocations using "objdump" command
echo "Extracting relocations using 'objdump'..."
objdump -r "$binary_file" > "$output_dir/${binary_name}_relocations.txt"

echo "Extraction complete. Results written to $output_dir."