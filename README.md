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

### Infrastructure
- HTTP server setup with Axum framework
- Health check endpoint (/health)
- Status endpoint (/status)
- Request tracing middleware
- CORS support

### Nausf_UEAuthentication Endpoints
- POST /ue-authentications (authentication initiation)
- PUT /ue-authentications/{authCtxId}/5g-aka-confirmation (5G AKA confirmation)

### Authentication Logic
- KAUSF key derivation (KDF function)
- UDM client implementation (Nudm_UEAuthentication_Get service)
- Authentication vector retrieval from UDM
- HXRES* computation from XRES*
- KSEAF key derivation
- RES* verification logic
- Authentication context storage and management

## NOT IMPLEMENTED FEATURES

### Nausf_UEAuthentication Endpoints
- POST /ue-authentications/{authCtxId}/eap-session (EAP session handling)
- POST /ue-authentications/deregister (deregistration)
- DELETE /ue-authentications/{authCtxId}/5g-aka-confirmation (delete 5G AKA result)
- DELETE /ue-authentications/{authCtxId}/eap-session (delete EAP result)

### Authentication Logic - 5G AKA Components
- Resynchronization handling (SQN mismatch)

### Authentication Logic - Other
- EAP-AKA' authentication method implementation
- Authentication vector validation

### Identity and Security
- SUPI/SUCI identity handling
- Serving Network Name (SNN) verification
- Home network authentication checks
- PLMN ID validation

### Service Endpoints
- SoR Protection endpoint (Nausf_SoRProtection)
- UPU Protection endpoint (Nausf_UPUProtection)

### Infrastructure
- HTTP/2 support
- TLS/mTLS support
- MongoDB integration (if needed)
- NRF integration (service discovery and registration)
- UDM client (Nudm_UEAuthentication)
- OAuth2 token validation

### Compliance
- OpenAPI schema validation
- 3GPP Problem Details format (TS 29.500)
- API versioning support

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
