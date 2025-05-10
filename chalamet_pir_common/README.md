# ChalametPIR Common

Common Utilities for ChalametPIR: Private Information Retrieval for Key-Value Databases.

This crate provides common utilities and data structures used by both the client and server implementations of the ChalametPIR protocol.  It includes:

- Matrix operations: A `Matrix` struct for efficient matrix manipulation, including multiplication and addition.
- Binary Fuse Filter: Implementation of Binary Fuse Filters for encoding key-value databases.
- Error handling: A unified `ChalametPIRError` enum for reporting errors across the client and server.
- Parameters: Constants and parameters used in the ChalametPIR protocol.

> [!NOTE]
> This crate is not supposed to be used by you on its own, rather it is a common dependency of both `chalamet_pir_server` and `chalamet_pir_client` crates.
