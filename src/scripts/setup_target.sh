#!/bin/bash

if [ ! -f $1 ]; then
    echo "Usage: $0 <binary>"
    exit 1
fi

binary_path=$1
echo $binary_path

binary_name=$(basename "$binary_path" | cut -d. -f1)
echo $binary_name

script_dir=$(dirname "$0")
data_dir="$script_dir/../../data/$binary_name"
mkdir -p $data_dir

echo $(file "$binary_path")

# basic info
file "$binary_path" > "$data_dir/$binary_name.file_info"
# objdump -d "$binary_path" > "$data_dir/$binary_name.objdump"
# objdump -h "$binary_path" > "$data_dir/$binary_name.sections"
# strings "$binary_path" > "$data_dir/$binary_name.strings"
# nm -g -C "$binary_path" | awk '$2=="T" || $2=="U" {print substr($0, index($0,$3))}' > "$data_dir/$binary_name.functions"

echo "Basic info saved to $data_dir"

r2_dir="$data_dir/r2"

echo "r2_dir: $r2_dir"
mkdir -p $r2_dir

# run r2 base script
python $script_dir/r2_base.py $binary_path $r2_dir