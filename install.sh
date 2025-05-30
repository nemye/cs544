#!/bin/bash
# Set default build type to DEBUG
CMAKE_BUILD_TYPE="DEBUG"

# Check if CMAKE_BUILD_TYPE argument is provided
if [ "$#" -gt 0 ]; then
  CMAKE_BUILD_TYPE=$1
fi

cd $(dirname "$0")
mkdir -p build
mkdir -p bin
mkdir -p lib
cd build
cmake .. -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE && cmake --build . -j 8 && cmake --install . --prefix ../
cd ..

# generate certs
echo $(pwd)
cd certs
./gencert.sh
cd ..