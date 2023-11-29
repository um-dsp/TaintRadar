#!/bin/bash

# Set the directory path
directory_path="/home/umd-user/Desktop/navex_project/navex_tests/faqforge-1.3.2"

# Change to the specified directory
cd "$directory_path" || exit

# Loop through each file in the directory
for file in $(find ./ -name '*.inc*'); do
    # Check if the file exists and is a regular file
    if [ -f "$file" ]; then
        # Rename the file by adding ".php" to the end
        new_name="${file%.inc}.php"
        mv "$file" "$new_name"
        echo "Renamed: $file to $new_name"
    else
        echo "Skipping: $file (not a regular file)"
    fi
done
