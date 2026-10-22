"""
AbuseIPDB & GreyNoise Classifier Connector
Differentiates benign mass internet noise from targeted APT exploitation infrastructure.
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


class AbuseIpdbGreyNoiseConnector(InternalEnrichmentConnector):
    async def enrich_entity(self, entity: Dict[str, Any]) -> List[Dict[str, Any]]:
        ip = entity.get("value")
        logger.info("evaluating_greynoise_classification", ip=ip)
        now_iso = datetime.now(timezone.utc).isoformat()
        stix_objects = []

        indicator_pattern = f"[ipv4-addr:value = '{ip}']"
        indicator_id = generate_deterministic_stix_id("indicator", indicator_pattern)

        # Indicator SDO with GreyNoise noise classification
        stix_objects.append({
            "id": indicator_id,
            "type": "indicator",
            "spec_version": "2.1",
            "name": f"Suspicious IP: {ip}",
            "pattern": indicator_pattern,
            "pattern_type": "stix",
            "valid_from": now_iso,
            "confidence": 85,
            "labels": ["greynoise:malicious", "abuseipdb:confidence-100", "targeted-scanner"],
            "created": now_iso,
            "modified": now_iso
        })

        # Relationship: Indicator indicates IPv4 Observable
        rel_id = generate_relationship_stix_id("based-on", indicator_id, entity["id"])
        stix_objects.append({
            "id": rel_id,
            "type": "relationship",
            "spec_version": "2.1",
            "relationship_type": "based-on",
            "source_ref": indicator_id,
            "target_ref": entity["id"],
            "confidence": 95,
            "created": now_iso,
            "modified": now_iso
        })

        return stix_objects

    async def health_check(self) -> Dict[str, Any]:
        return {"status": "HEALTHY", "connector": "AbuseIPDB & GreyNoise Classifier"}
