# OpenCTI ATIP Platform - Connector Builder Workflow

This guide establishes the autonomous and human-in-the-loop workflow for developing, testing, and deploying connectors for the Autonomous Threat Intelligence Platform (ATIP).

---

## 1. Connector Taxonomy Overview

ATIP categorizes connectors into three distinct execution archetypes:

| Archetype | Lifecycle Pattern | Primary Input | Primary Output | Typical Use Cases |
| :--- | :--- | :--- | :--- | :--- |
| **External Import** | Scheduled / Cron Poller | Remote APIs, RSS, TAXII, S3 | STIX 2.1 Bundles (`atip.ingest.raw`) | CISA KEV, MITRE ATT&CK, ThreatFox, AlienVault OTX |
| **Internal Enrichment** | Reactive / Event-Driven Stream Consumer | Single SDO / SCO from `atip.enrichment.requests` | Enriched SDO / SCO + New SROs (`atip.ingest.raw`) | VirusTotal, Shodan, GreyNoise, AbuseIPDB |
| **Internal Analysis** | Batch or CDC Stream Consumer | Raw Unstructured Text, Logs, Subgraphs | Defanged Observables, Attack-Patterns, Sigma Rules | LLM IOC Defanging, Sigma Rule Synthesizer, NLP TTP Extractor |

---

## 2. Architecture & Design Principles

### 2.1 Deterministic STIX 2.1 UUIDv5 Identifiers
To guarantee idempotency and avoid duplicate nodes across diverse feed sources:
- Never generate random UUIDv4 identifiers for STIX entities.
- Use `atip_sdk.stix_id.generate_deterministic_stix_id(stix_type, canonical_value)` from `@opencti/atip-sdk`.
- STIX Namespace: `00abedb4-aa42-466c-9c01-fedf7a7a527b` (OASIS standard namespace).
- Standard canonical keys:
  - `indicator` $\rightarrow$ canonical pattern (e.g. `[ipv4-addr:value = '198.51.100.1']`)
  - `ipv4-addr` $\rightarrow$ canonical IP value (e.g. `198.51.100.1`)
  - `vulnerability` $\rightarrow$ uppercase CVE ID (e.g. `CVE-2024-21887`)
  - `attack-pattern` $\rightarrow$ MITRE External ID or canonical technique name (e.g. `T1190`)
  - `malware` $\rightarrow$ lowercase normalized family name (e.g. `kv-botnet`)
  - `relationship` $\rightarrow$ `{relationship_type}::{source_ref}::{target_ref}`

### 2.2 Rate Limiting
External APIs impose strict token limits (e.g. VirusTotal 4 req/min on public tiers, Shodan 1 req/sec). Connectors must instantiate:
```python
from atip_sdk.rate_limiter import RedisTokenBucketRateLimiter

rate_limiter = RedisTokenBucketRateLimiter(
    redis_client=redis_client,
    key="ratelimit:virustotal",
    capacity=4,
    refill_rate=4.0 / 60.0  # 4 tokens per minute
)
await rate_limiter.acquire()
```

### 2.3 Confidence & TLP Modeling
All connectors must attach metadata to generated SDOs:
- `confidence`: Integer between 0 and 100 based on source fidelity.
- `object_marking_refs`: Standard STIX 2.1 marking definition (e.g. `marking-definition--613f2e26-407d-48c7-9ece-e8f335779b37` for TLP:CLEAR).
- `created_by_ref`: Identity SDO identifying the connector agent.

---

## 3. Step-by-Step Implementation Guide

### Step 1: Subclass the Appropriate Base Connector
Inherit from `atip_sdk.base_connector.BaseConnector` or its specialized variants:
- `ExternalImportConnector`
- `InternalEnrichmentConnector`
- `InternalAnalysisConnector`

### Step 2: Implement the `collect()` / `enrich()` Method
- Fetch data from the upstream service.
- Transform JSON/XML/CSV into valid STIX 2.1 SDOs and SCOs.
- Calculate deterministic STIX IDs using `generate_deterministic_stix_id`.
- Build STIX 2.1 SROs (Relationships) linking entities (`uses`, `targets`, `communicates-with`, `indicates`, `attributed-to`).

### Step 3: Bundle & Produce to Kafka
Call `self.publish_bundle(stix_bundle)` to serialize and publish the STIX bundle onto Redpanda/Kafka (`atip.ingest.raw`).

### Step 4: Health Check & Telemetry
Provide a `health_check()` implementation validating:
- Upstream network reachability.
- API key validity.
- Redis & Kafka connection status.

---

## 4. Verification & Testing

Every connector must include:
1. Unit tests with mocked external APIs.
2. STIX 2.1 JSON Schema validation against `packages/stix-schema-registry`.
3. Idempotency test: Ingesting the identical payload twice produces 0 duplicated UUIDs and preserves graph topology.
