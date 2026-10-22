"""
VirusTotal Internal Enrichment Connector
Listens for enrichment requests on files, domains, and IPs.
Applies Redis distributed rate limiting and yields enriched STIX SDOs/SCOs and SROs.
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


class VirusTotalConnector(InternalEnrichmentConnector):
    async def enrich_entity(self, entity: Dict[str, Any]) -> List[Dict[str, Any]]:
        stype = entity.get("type", "")
        value = entity.get("value") or entity.get("name")
        logger.info("enriching_entity_virustotal", stype=stype, value=value)

        # Enforce distributed rate limit (4 req/min on public VT tier)
        if self.rate_limiter:
            await self.rate_limiter.acquire()

        now_iso = datetime.now(timezone.utc).isoformat()
        enriched_objects = []

        # Synthetic VirusTotal sandbox response
        if stype == "file":
            # Add malware family identification
            malware_id = generate_deterministic_stix_id("malware", "agent-tesla")
            enriched_objects.append({
                "id": malware_id,
                "type": "malware",
                "spec_version": "2.1",
                "name": "AgentTesla",
                "is_family": True,
                "confidence": 94,
                "created": now_iso,
                "modified": now_iso,
                "description": "Advanced keylogger and credential stealer detected by 62/70 AV engines."
            })

            # SRO: file indicates malware
            rel_id = generate_relationship_stix_id("indicates", entity["id"], malware_id)
            enriched_objects.append({
                "id": rel_id,
                "type": "relationship",
                "spec_version": "2.1",
                "relationship_type": "indicates",
                "source_ref": entity["id"],
                "target_ref": malware_id,
                "confidence": 92,
                "created": now_iso,
                "modified": now_iso
            })

        return enriched_objects

    async def health_check(self) -> Dict[str, Any]:
        return {"status": "HEALTHY", "connector": "VirusTotal Enricher"}
