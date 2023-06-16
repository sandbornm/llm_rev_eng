#!/bin/bash

binary_file="path/to/binary"  # Replace with the path to your binary file
output_file="output.json"     # Replace with the desired output file name

# Execute objdump and store the disassembly output in a variable
disassembly=$(objdump -d "$binary_file")

# Parse the disassembly and generate the JSON structure
json=$(echo "$disassembly" | awk -v RS='' '/<.*>:/ {gsub(/<|>/,"",$0); func=$0; getline; sub(/^[[:xdigit:]]+:/,"",$0); disasm=$0; print "\"" func "\": \"" disasm "\","}')

# Remove the trailing comma
json=${json%,}

# Wrap the JSON dictionary structure
json="{$json}"

# Write the JSON to the output file
echo "$json" > "$output_file"

echo "JSON file with function disassembly created: $output_file"
