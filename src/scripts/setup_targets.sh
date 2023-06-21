#!/bin/bash

# process all targets in the specified directory
# assume target dir is flat and only contains binaries
# of interest to be analyzed
target_dir=($realpath $1)
echo $target_dir

script_dir=$(dirname "$0")
echo $script_dir

if [ ! -d "$target_dir" ]; then
    echo "Usage: $0 <target_dir>"
    exit 1
fi

echo "target_dir: $target_dir"
for target_file in `ls $target_dir`
do
    target_path="$target_dir/$target_file"
    echo "target file is: $target_path"
    "$script_dir/setup_target.sh" "$target_path"
done
