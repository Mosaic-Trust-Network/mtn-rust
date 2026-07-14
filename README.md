# Internet of People

Internet of People (IoP) is a software project creating a decentralized software stack that provides the building blocks and tools to support a decentralized society.

This repository contains our Rust codebase that serves as common implementation and used with different bindings (WebAssembly, C FFI) in SDKs for other languages like Typescript or Dart as well.

## Usage

After installing Rust using [rustup](https://rustup.rs/), use the `iop-sdk` crate with the latest version as a dependency with `cargo` in file `Cargo.toml` of your project.

## Overview

You can read a  overview and descriptions of different components on our [Mosaic DID Paper](https://sovereign-society.org/papers/mosaic-did/).

## Components

- `json-digest` provides a canonical Json format, derived content IDs and
  selectively building [Merkle trees](https://en.wikipedia.org/wiki/Merkle_tree)
  from parts of a Json document
- `keyvault` implements a "generic cryptographic calculator": starting from a list of words
  it can deterministically derive an enormous number of private keys for any purpose
  like cryptocurrency addresses, DIDs, device keys, etc.
- `vault` adds encryption support, pluggability with state handling and persistence to the pure calculator features of the `keyvault`
- `mosaic-did-types` provides types used in protocols between blockchain code and application code
- `sdk` exports features of libraries above for clients in a single crate
- `pallet-mosaic-did` is a Polkadot SDK component that can be added to a blockchain runtime to keep and update DID state using a
  consensus among multiple participants.
