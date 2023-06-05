#!/bin/bash

# usage: ./detect_packer.sh binaryfile

file=$1

if [ -z "$file" ]; then
    echo "No binary file specified."
    exit 1
fi

if [ ! -f "$file" ]; then
    echo "File not found."
    exit 1
fi

# Perform entropy analysis using binwalk
binwalk --entropy --save $file

# Check if a .png file (entropy plot) was created
if [ -f "$file.png" ]; then
    echo "Entropy analysis completed. See $file.png for the entropy plot."
else
    echo "Failed to perform entropy analysis."
fi
