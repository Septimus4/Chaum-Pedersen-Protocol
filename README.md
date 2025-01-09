# Chaum-Pedersen Protocol

This project is an implementation of the Chaum-Pedersen protocol, a zero-knowledge proof (ZKP) system that allows one to prove the equality of discrete logarithms in two different groups without revealing the actual logarithm. The primary goal of this project is to deepen my understanding of zero-knowledge proofs and to enhance my proficiency in Rust programming.

## Table of Contents

- [Goal](#goal)
- [File Structure](#file-structure)
- [Installation](#installation)
- [Usage](#usage)

## Goal

The main objective of this project is educational. By implementing the Chaum-Pedersen protocol, I aim to:

- Gain a deeper understanding of zero-knowledge proofs and their applications in cryptography.
- Enhance my skills in Rust by applying them to a practical cryptographic protocol.

## File Structure

The project repository is organized as follows:

- **chaum_pedersen/src**: Contains the core implementation of the Chaum-Pedersen protocol.
  - `lib.rs`: Core protocol logic and functions.
- **proto/**: Houses protocol buffer definitions for gRPC communication.
  - `auth.proto`: Defines the gRPC service and message types for zero-knowledge proof authentication.
- **src/**: Contains the main source code for the application.
  - `prover.rs`: Implementation of the client-side application.
  - `auth.rs`: Library module for shared functionality.
  - `verifier.rs`: Implementation of the server-side application.
- `build.rs`: Build script for custom build processes, such as compiling protocol buffers.

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/Septimus4/Chaum-Pedersen-Protocol.git
   cd Chaum-Pedersen-Protocol
   ```

2. **Ensure you have Rust installed**. If not, install it from [rust-lang.org](https://www.rust-lang.org/).

3. **Build the project**:

   ```bash
   cargo build --release
   ```

## Usage

After building the project, you can run the server and client applications to perform the Chaum-Pedersen protocol operations.

1. **Run the server**:

   ```bash
   ./target/release/verifier
   ```

2. **Run the client**:

   ```bash
   ./target/release/prover
   ```
