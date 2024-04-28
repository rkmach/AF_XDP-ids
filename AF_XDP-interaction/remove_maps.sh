#!/bin/bash

# Directory to delete files from
directory="/sys/fs/bpf/amigo"

# Check if the directory exists
if [ -d "$directory" ]; then
    # Delete all files and directories recursively
    rm -f "$directory"/*
    echo "All files and directories in $directory have been deleted."
else
    echo "Directory $directory does not exist."
fi
