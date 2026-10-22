# ATIP Python SDK

Core Python SDK for the OpenCTI Autonomous Threat Intelligence Platform (ATIP).

## Modules
- `atip_sdk.stix_id`: Deterministic OASIS STIX 2.1 UUIDv5 identifier generator.
- `atip_sdk.rate_limiter`: Distributed Redis Token Bucket rate limiter with atomic Lua script.
- `atip_sdk.base_connector`: Abstract lifecycle framework for external pollers and enrichment agents.
