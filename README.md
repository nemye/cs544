This C++ software package contains code for the implementation of the SPOQ protocol.

Dependencies:
CMake >= 3.16

Compilers tested:
g++ 13.1

OS tested:
Ubuntu 22.04 LTS

Prerequisites:
-Follow steps to install msquic https://github.com/microsoft/msquic/blob/main/docs/BUILD.md
-msquic should install such that the directory structure is spoq/msquic
    -If you are unable to install it there, update the top level CMakeLists.txt to point at the msquic install root
-Note it is important to install as statically linked using powershell:
    -./scripts/build.ps1 Release -Static

To compile all SPOQ executables and requried certs for testing,
simply run "install.sh" from any directory.
Ex: ./install.sh (same as calling ./install.sh DEBUG)
./install.sh RELEASE
./install.sh RELWITHDEBINFO

An executable for the client and server will be installed in /bin.

To test perform the following steps:
Open a terminal:
1. ./run_server.sh

From a separate terminal:
2. ./run_client.sh

You should see messages demonstrating progression through the SPOQ states. 