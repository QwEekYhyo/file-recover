#!/bin/bash
# Usage: ./find_hash.sh <file> <directory>

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <file> <directory>"
    exit 1
fi

file="$1"
search_dir="$2"

if [ ! -f "$file" ]; then
    echo "Error: '$file' is not a valid file."
    exit 1
fi

if [ ! -d "$search_dir" ]; then
    echo "Error: '$search_dir' is not a valid directory."
    exit 1
fi

echo "Calculating hash of target file..."
hash=$(sha256sum "$file" | awk '{print $1}')

echo "Searching for duplicates of '$file' in '$search_dir'..."
find "$search_dir" -type f -exec sha256sum {} + | grep "$hash" | while read -r line; do
    dup_file=$(echo "$line" | awk '{print $2}')
    if [ "$dup_file" != "$file" ]; then
        echo "Duplicate found: $dup_file"
    fi
done
