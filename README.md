Tencoin (TEC)

""License: MIT" (https://img.shields.io/badge/License-MIT-blue.svg)" (LICENSE)
""Network Status" (https://img.shields.io/badge/Network-Mainnet-green.svg)"

Tencoin (TEC) is a decentralized peer-to-peer cryptocurrency that combines Bitcoin's proven UTXO architecture with native consensus-enforced conditional transactions.

Tencoin enables secure value transfers, timelocks, hashlocks, refundable payments, and secret-based redemption directly at the transaction output level without requiring smart contracts, external execution environments, or trusted intermediaries.

🌐 Official Website: https://tencoin.org

---

Whitepaper

The official Tencoin Whitepaper is available here:

📄 "Tencoin Whitepaper" (./whitepaper/tencoin.pdf)

---

Table of Contents

- Introduction
- Network Parameters
- Key Features
- Technical Overview
- Running a Node
- Development Status
- Contributing
- License

---

Introduction

Tencoin is a Proof-of-Work cryptocurrency designed for secure peer-to-peer electronic payments.

The network uses a UTXO-based transaction model and extends traditional transaction functionality through Native Conditional Outputs, allowing spending conditions to be enforced directly by consensus rules.

Unlike account-based smart contract platforms, Tencoin maintains a simple and deterministic validation model while supporting advanced transaction flows.

---

Network Parameters

Parameter| Value
Ticker| TEC
Consensus| Proof-of-Work (SHA-256)
Maximum Supply| 10,000,000 TEC
Block Time| 5 Minutes
Initial Block Reward| 50 TEC
Halving Interval| Every 100,000 Blocks
Smallest Unit| Teno
P2P Port| 10110
RPC Port| 10111

---

Key Features

Native Conditional Outputs

Tencoin introduces consensus-enforced conditional outputs that allow coins to be spent only when predefined conditions are satisfied.

Supported transaction types include:

- Standard UTXO Transfers
- Timelock Outputs
- Hashlock Outputs
- Refundable Transfers
- Secret-Code Protected Payments

All conditions are validated by full nodes and enforced by consensus rules.

Proof-of-Work Security

Tencoin uses SHA-256 Proof-of-Work consensus.

Blocks are secured through computational work, and the valid chain with the greatest cumulative proof-of-work is considered authoritative by the network.

UTXO-Based Architecture

Tencoin follows the UTXO model pioneered by Bitcoin.

This approach provides:

- Deterministic validation
- Transparent ownership tracking
- Efficient transaction verification
- Simplified Payment Verification (SPV)

Peer-to-Peer Network

Nodes communicate through a decentralized peer-to-peer network.

The network is designed to operate without central coordination while maintaining consensus through Proof-of-Work.

Mainnet ports:

- P2P: "10110"
- RPC: "10111"

JSON-RPC Interface

Tencoin provides a JSON-RPC interface for:

- Wallet software
- Blockchain explorers
- Monitoring tools
- Application integrations
- Node management

---

Technical Overview

Transaction Model

Transactions consume existing UTXOs and create new outputs.

Each output may contain:

- Standard ownership conditions
- Timelock conditions
- Hashlock conditions
- Refund rules
- Additional consensus-supported constraints

Outputs that fail validation requirements cannot be spent.

Consensus Validation

Every fully validating node independently verifies:

- Proof-of-Work
- Block structure
- Transaction validity
- UTXO availability
- Conditional output requirements
- Consensus rules

Invalid blocks are rejected by the network.

Monetary Policy

Tencoin has a fixed maximum supply of:

10,000,000 TEC

New coins are introduced through block rewards and distributed to miners.

The block subsidy begins at:

50 TEC per block

and is reduced by half every:

100,000 blocks

---

Running a Node

The Tencoin node is being implemented in Rust.

Requirements

- Rust toolchain
- Cargo
- Git

Install Rust and Cargo using the official Rust installation instructions:

https://www.rust-lang.org/tools/install

Clone Repository

git clone https://github.com/TenCoinOrg/TenCoin.git
cd TenCoin

Build the Rust Node

If the Rust node is configured as a Cargo project at the repository root, run:

cargo build --release

Run the Rust Node

The execution command depends on the Rust binary target defined by the project.

If the binary target is named "tencoin-node", run:

cargo run --release --bin tencoin-node

Replace "tencoin-node" with the actual binary target name if it differs.

For a production release, use the compiled executable generated in the "target/release/" directory.

---

Development Status

⚠️ Tencoin is under active development.

Features, APIs, consensus rules, network behavior, and software components may change between releases until the protocol reaches long-term stability.

The current whitepaper reflects the intended protocol design and may evolve as implementation progresses.

---

Contributing

Contributions, code reviews, bug reports, testing, and protocol discussions are welcome.

Please open an issue or submit a pull request to participate in development.

---

License

Released under the MIT License.

See the LICENSE file for details.