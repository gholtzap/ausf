# 5G AUSF (Authentication Server Function)

A Rust implementation of the 5G Authentication Server Function based on 3GPP specifications.

## Overview

The AUSF is a key network function in 5G core networks responsible for authentication operations. This implementation follows the 3GPP TS 29.509 specification.

## Supported Services

Based on the 3GPP OpenAPI specifications in `context/3gpp/`:

- **Nausf_UEAuthentication**: UE authentication service
- **Nausf_SoRProtection**: Steering of Roaming protection service
- **Nausf_UPUProtection**: UE Parameters Update protection service

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
- DELETE /ue-authentications/{authCtxId}/5g-aka-confirmation (delete 5G AKA result)
- POST /ue-authentications/deregister (deregistration)

### Authentication Logic
- KAUSF key derivation (KDF function)
- UDM client implementation (Nudm_UEAuthentication_Get service)
- Authentication vector retrieval from UDM
- HXRES* computation from XRES*
- KSEAF key derivation
- RES* verification logic
- Authentication context storage and management

### Identity and Security
- Serving Network Name (SNN) verification
- Authentication vector validation (RAND, XRES*, AUTN, KAUSF field validation)
- SUPI/SUCI identity handling (parsing and format validation)
- PLMN ID validation (MCC/MNC extraction and validation)
- Home network authentication checks

### Resynchronization
- Resynchronization handling (SQN mismatch) via AUTS

### Compliance
- 3GPP Problem Details format (TS 29.500) for error responses

### NRF Integration - Infrastructure
- NRF client HTTP implementation
- NRF client configuration and connection handling

### NRF Integration (Nnrf_NFManagement)
- NFRegister operation (register AUSF with NRF on startup)
- AUSF profile management (NF instance ID, PLMN, capacity, priority)
- Heartbeat mechanism (keep-alive with NRF)

### NRF Integration (Nnrf_NFDiscovery)
- NFDiscover operation (discover other NFs like UDM)
- Dynamic UDM service discovery on startup
- Automatic UDM endpoint configuration via NRF

### NRF Integration - Lifecycle Management
- NFUpdate operation (update AUSF profile dynamically)
- NFDeregister operation (graceful deregistration on shutdown)
- Admin endpoint for manual profile updates (PATCH /admin/nf-profile)

### Persistence
- MongoDB integration for authentication context storage
- Binary data serialization for cryptographic keys
- Async database operations with connection pooling

### Protocol Support
- HTTP/2 support with automatic protocol negotiation
- HTTP/1.1 backward compatibility
- Graceful shutdown handling

### Security
- TLS/mTLS support with rustls
- Client certificate verification for mTLS
- Configurable TLS certificates and keys
- Automatic ALPN negotiation (h2, http/1.1)

### EAP-AKA' Support
- EAP packet structures (Code, Identifier, Length, Type)
- EAP-AKA' message types and subtypes (Challenge, Authentication-Reject, Synchronization-Failure, Identity, Notification, Reauthentication, Client-Error)
- EAP-AKA' attribute types and structures (AT_RAND, AT_AUTN, AT_RES, AT_AUTS, AT_MAC, AT_KDF, AT_KDF_INPUT, AT_IDENTITY, AT_COUNTER, AT_NONCE_S, etc.)
- EAP packet serialization and deserialization
- EAP-AKA' message parsing and building

## NOT IMPLEMENTED FEATURES

### Nausf_UEAuthentication Endpoints
- POST /ue-authentications/{authCtxId}/eap-session (EAP session handling)
- DELETE /ue-authentications/{authCtxId}/eap-session (delete EAP result)

### Authentication Logic - EAP-AKA' (Remaining)
- EAP-AKA' key derivation (CK', IK', MK, K_aut, K_encr, K_re, MSK, EMSK)
- EAP-AKA' state machine (IDLE, IDENTITY, CHALLENGE, SUCCESS, FAILURE)
- EAP-AKA' authentication vector processing
- EAP-AKA' MAC and AT_MAC attribute computation
- EAP-AKA' AT_AUTN and AT_RES validation
- EAP-AKA' resynchronization handling (AT_AUTS)
- EAP-AKA' fast re-authentication support

### Service Endpoints
- SoR Protection endpoint (Nausf_SoRProtection)
- UPU Protection endpoint (Nausf_UPUProtection)

### Infrastructure
- OAuth2 token validation

### NRF Integration (Nnrf_NFManagement)
- NFStatusSubscribe operation (subscribe to NF status changes)

### Compliance
- OpenAPI schema validation
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
- TLS configuration (optional):
  - TLS_CERT_PATH: Path to TLS certificate file
  - TLS_KEY_PATH: Path to TLS private key file
  - TLS_CLIENT_CA_PATH: Path to client CA certificate for mTLS (optional)

### Building

```bash
cargo build
```

### Running

```bash
cargo run
```