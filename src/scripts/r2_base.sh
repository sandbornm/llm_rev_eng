#!/bin/bash

# Usage: /Users/michael/GradSchool/Summer2023/llm_rev_eng/src/scripts/radare_overview.sh binaryfile

binary=$1

if [ -z "$binary" ]; then
    echo "No binary file specified."
    exit 1
fi

if [ ! -f "$binary" ]; then
    echo "File not found."
    exit 1
fi

binary_name=$(basename "$binary" | cut -d. -f1)
output_dir="../../data/$binary_name"

mkdir -p "$output_dir"

# basic info about the binary file
r2 -qc "iIj" "$binary" > "$output_dir/binary_info.json"

# functions
r2 -qc "aflj" "$binary" > "$output_dir/functions.json"

r2 -qc "iij" "$binary" > "$output_dir/imports.json"
r2 -qc "iEj" "$binary" > "$output_dir/exports.json"
r2 -qc "iSj" "$binary" > "$output_dir/sections.json"
r2 -qc "ihj" "$binary" > "$output_dir/header.json"
r2 -qc "izj" "$binary" > "$output_dir/strings.json"
