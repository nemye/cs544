# SPOQ Protocol

This C++ software package contains code for the implementation of the SPOQ protocol for CS544 at Drexel University.

## Dependencies

- CMake >= 3.16
- msquic

## Compilers Tested

- g++ 13.1

## OS Tested

- Ubuntu 22.04 LTS

## Prerequisites

- Follow steps to install msquic https://github.com/microsoft/msquic/blob/main/docs/BUILD.md
- msquic should install such that the directory structure is spoq/msquic
- If you are unable to install it there, update the top level CMakeLists.txt to point at the msquic install root
- Note it is important to install msquic as statically linked using powershell:
  ```
  ./scripts/build.ps1 Release -Static
  ```
- If you must link dynamically, you're on your own.

## Installation

To compile all SPOQ executables and requried certs for testing, simply run "install.sh" from any directory.

### Examples

```bash
./install.sh (same as calling ./install.sh DEBUG)
./install.sh RELEASE
./install.sh RELWITHDEBINFO
```

An executable for the client and server will be installed in /bin.

## Usage

### Client Usage

```bash
/bin/spoq_client -help
bin/spoq_client -cert_file:./certs/client_cert.pem -key_file:./certs/client_key.pem -ca_file:./certs/ca_cert.pem -target:127.0.0.1
```

### Server Usage

```bash
/bin/spoq_client -help
bin/spoq_server -cert_file:./certs/server_cert.pem -key_file:./certs/server_key.pem -ca_file:./certs/ca_cert.pem
```

## Certificate Generation

Proper certificates for local testing will be generated during the installation process or can be manually created using:

```bash
certs/gencert.sh
```

## Testing

To test perform the following steps:

1. Open a terminal:
   ```bash
   ./run_server.sh
   ```

2. From a separate terminal:
   ```bash
   ./run_client.sh
   ```

## Learnings & Notes

You should see messages demonstrating progression through the SPOQ states. The nominal path is followed with successful version negotation. Failure test cases and robust JSON parsing are omitted, but other behaviors can be observed by changinging to run scripts and libraries such as nlohmann JSON exist.

During implementation of the SPOQ application protocol, I realized per message authentication was not worth doing and instead opted for mutual TLS (mTLS) connection. I also decided to skip a fixed size message head and sync word by using new-line delimited json. This still supports variable message size without wasting the 4 extra bytes.

This code is a hodge-podge of C and C++, so future work would entail modernizing to C++20 standards and syntax.
