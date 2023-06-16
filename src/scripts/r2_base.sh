#!/bin/bash

binary_path=$1
echo $binary_path

binary_name=$(basename "$binary_path" | cut -d. -f1)

output_dir="../../data/$binary_name/r2"
mkdir -p $output_dir

r2 -qc "iIj" "$binary" > "$output_dir/binary_info.json"
r2 -qc "aflj" "$binary" > "$output_dir/functions.json"
r2 -qc "iij" "$binary" > "$output_dir/imports.json"
r2 -qc "iEj" "$binary" > "$output_dir/exports.json"
r2 -qc "iSj" "$binary" > "$output_dir/sections.json"
r2 -qc "ihj" "$binary" > "$output_dir/header.json"
r2 -qc "izj" "$binary" > "$output_dir/strings.json"
