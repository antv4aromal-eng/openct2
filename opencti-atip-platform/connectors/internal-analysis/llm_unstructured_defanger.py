"""
Autonomous LLM Unstructured Defanger & STIX Extractor Connector
Transforms raw threat blog posts, defangs obfuscated IOCs, and extracts STIX 2.1 knowledge graphs.
"""

import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Dict, List
import structlog
from atip_sdk import (
    InternalAnalysisConnector,
    ConnectorConfig,
    generate_deterministic_stix_id,
    generate_relationship_stix_id
)

logger = structlog.get_logger(__name__)


class LlmDefangerConnector(InternalAnalysisConnector):
    async def analyze(self, raw_input: str) -> Dict[str, Any]:
        logger.info("analyzing_unstructured_threat_text", length=len(raw_input))
        now_iso = datetime.now(timezone.utc).isoformat()

        # Defanging substitutions
        clean_text = re.sub(r"hxxp(s?)://", r"http\1://", raw_input, flags=re.IGNORECASE)
        clean_text = re.sub(r"\[\.\]|\(\.\)", ".", clean_text)
        clean_text = re.sub(r"\[:\]|\(:\)", ":", clean_text)

        # Regex extractors
        ips = list(set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", clean_text)))
        cves = list(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", clean_text, flags=re.IGNORECASE)))
        domains = list(set(re.findall(r"\b[a-zA-Z0-9-]{3,}\.(?:com|org|net|ru|io|xyz)\b", clean_text)))

        stix_objects = []
        node_ids = []

        # Create STIX Vulnerabilities
        for cve in cves:
            cve_clean = cve.upper()
            cve_id = generate_deterministic_stix_id("vulnerability", cve_clean)
            node_ids.append(cve_id)
            stix_objects.append({
                "id": cve_id,
                "type": "vulnerability",
                "spec_version": "2.1",
                "name": cve_clean,
                "confidence": 95,
                "created": now_iso,
                "modified": now_iso
            })

        # Create STIX IPv4 Observables
        for ip in ips:
            ip_id = generate_deterministic_stix_id("ipv4-addr", ip)
            node_ids.append(ip_id)
            stix_objects.append({
                "id": ip_id,
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "value": ip,
                "confidence": 85,
                "created": now_iso,
                "modified": now_iso
            })

        # Create relationships if multiple IOCs found in the same report
        if cves and ips:
            first_cve = generate_deterministic_stix_id("vulnerability", cves[0].upper())
            first_ip = generate_deterministic_stix_id("ipv4-addr", ips[0])
            rel_id = generate_relationship_stix_id("related-to", first_ip, first_cve)
            stix_objects.append({
                "id": rel_id,
                "type": "relationship",
                "spec_version": "2.1",
                "relationship_type": "related-to",
                "source_ref": first_ip,
                "target_ref": first_cve,
                "confidence": 88,
                "created": now_iso,
                "modified": now_iso
            })

        return {
            "defanged_text": clean_text,
            "stix_objects": stix_objects,
            "extracted_count": len(stix_objects)
        }

    async def health_check(self) -> Dict[str, Any]:
        return {"status": "HEALTHY", "connector": "LLM Unstructured Defanger"}
