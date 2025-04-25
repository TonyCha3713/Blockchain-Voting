#!/usr/bin/bash

# cleanup_files.sh: Delete all .json and .pem files in each subdirectory (and root)
# Usage: ./cleanup_files.sh

set -euo pipefail

# Delete in the current directory
echo "Cleaning .json and .pem files in current directory..."
find . -maxdepth 1 -type f \( -name '*.json' -o -name '*.pem' \) -print -delete

# Loop over every subdirectory one level deep
for dir in */ ; do
  if [[ -d "$dir" ]]; then
    echo "Cleaning .json and .pem files in $dir"
    find "$dir" -maxdepth 1 -type f \( -name '*.json' -o -name '*.pem' \) -print -delete
  fi
done
