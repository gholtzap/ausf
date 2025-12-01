# 5G AUSF (Authentication Server Function)

A Rust implementation of the 5G Authentication Server Function based on 3GPP specifications.

## Overview

The AUSF is a key network function in 5G core networks responsible for authentication operations. This implementation follows the 3GPP TS 29.509 specification.

## Supported Services

Based on the 3GPP OpenAPI specifications in `context/3gpp/`:

- **Nausf_UEAuthentication**: UE authentication service
- **Nausf_SoRProtection**: Steering of Roaming protection service
- **Nausf_UPUProtection**: UE Parameters Update protection service

## Project Structure

```
ausf/
├── context/3gpp/      # 3GPP OpenAPI specifications
├── src/               # Source code
├── types/             # Type definitions
└── Cargo.toml         # Rust dependencies
```

## IMPLEMENTED FEATURES

(Features will be added here as they are completed)

## NOT IMPLEMENTED FEATURES

- UE Authentication endpoint
- SoR Protection endpoint
- UPU Protection endpoint
- MongoDB integration
- HTTP server setup
- OpenAPI schema validation
- Authentication token handling
- Logging and monitoring

## Development

### Prerequisites

- Rust (latest stable)
- MongoDB
- Development environment with OpenSSL

### Environment Variables

Copy `.env.example` to `.env` and configure:
- MongoDB connection string
- Server port and host
- Log level

### Building

```bash
cargo build
```

### Running

```bash
cargo run
```

## Standards Compliance

This implementation adheres to:
- 3GPP TS 29.509 V18.3.0 - Authentication Server Services
- 3GPP TS 29.501 - Principles and Guidelines for Services Definition

## License

TBD
