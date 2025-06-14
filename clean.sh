#!/bin/bash

# Clean script to remove build and bin directories
cd $(dirname "$0")

# Remove build directory
if [ -d "build" ]; then
    echo "Removing build directory..."
    rm -r build
fi

# Remove bin directory
if [ -d "bin" ]; then
    echo "Removing bin directory..."
    rm -r bin
fi

# Remove bin directory
if [ -d "lib" ]; then
    echo "Removing lib directory..."
    rm -r lib
fi

echo "Clean completed."
