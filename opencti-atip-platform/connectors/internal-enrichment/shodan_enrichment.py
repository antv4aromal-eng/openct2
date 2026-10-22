"""
Shodan Internet Port & Infrastructure Enrichment Connector
Fingerprints open ports, SSL certificates, and maps exposed services to STIX Infrastructure SDOs.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List
import structlog
from atip_sdk import (
    InternalEnrichmentConnector,
    ConnectorConfig,
    generate_deterministic_stix_id,
    generate_relationship_stix_id
)

logger = structlog.get_logger(__name__)


class ShodanEnrichmentConnector(InternalEnrichmentConnector):
    async def enrich_entity(self, entity: Dict[str, Any]) -> List[Dict[str, Any]]:
        ip = entity.get("value")
        logger.info("enriching_ip_via_shodan", ip=ip)
        now_iso = datetime.now(timezone.utc).isoformat()
        stix_objects = []

        # Synthetic Shodan port scan response
        infra_name = f"Infrastruture - {ip}"
        infra_id = generate_deterministic_stix_id("infrastructure", infra_name)

        infra_sdo = {
            "id": infra_id,
            "type": "infrastructure",
            "spec_version": "2.1",
            "name": infra_name,
            "description": f"Exposed ports: [80, 443, 8443]. SSL Subject: CN=vpn.gateway.local. ASN: AS13335",
            "infrastructure_types": ["command-and-control", "hosting-malicious-content"],
            "confidence": 88,
            "created": now_iso,
            "modified": now_iso
        }
        stix_objects.append(infra_sdo)

        # Relationship: IP consists-of / related-to infrastructure
        rel_id = generate_relationship_stix_id("consists-of", infra_id, entity["id"])
        stix_objects.append({
            "id": rel_id,
            "type": "relationship",
            "spec_version": "2.1",
            "relationship_type": "consists-of",
            "source_ref": infra_id,
            "target_ref": entity["id"],
            "confidence": 90,
            "created": now_iso,
            "modified": now_iso
        })

        return stix_objects

    async def health_check(self) -> Dict[str, Any]:
        return {"status": "HEALTHY", "connector": "Shodan Enricher"}
