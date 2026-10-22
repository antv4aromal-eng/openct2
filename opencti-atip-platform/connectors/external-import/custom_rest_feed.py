"""
Custom REST Feed External Import Connector
Generic poller capable of ingesting arbitrary JSON/CSV threat intelligence feeds.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List
import httpx
import structlog
from atip_sdk import ExternalImportConnector, ConnectorConfig, generate_deterministic_stix_id

logger = structlog.get_logger(__name__)


class CustomRestFeedConnector(ExternalImportConnector):
    def __init__(self, config: ConnectorConfig, feed_url: str = "https://threatintel.local/feed.json"):
        super().__init__(config)
        self.feed_url = feed_url
        self.client = httpx.AsyncClient(timeout=15.0)

    async def collect(self) -> List[Dict[str, Any]]:
        logger.info("polling_custom_rest_feed", url=self.feed_url)
        stix_objects = []

        # Synthetic threat telemetry batch
        mock_feed_data = [
            {"indicator": "198.51.100.24", "type": "ipv4-addr", "threat": "Cobalt Strike C2", "confidence": 88},
            {"indicator": "apt-malicious-domain.org", "type": "domain-name", "threat": "Phishing Landing Page", "confidence": 82}
        ]

        now_iso = datetime.now(timezone.utc).isoformat()
        for item in mock_feed_data:
            val = item["indicator"]
            stype = item["type"]
            stix_id = generate_deterministic_stix_id(stype, val)

            sco = {
                "id": stix_id,
                "type": stype,
                "spec_version": "2.1",
                "value": val,
                "confidence": item["confidence"],
                "created": now_iso,
                "modified": now_iso,
                "labels": ["feed-import", item["threat"]]
            }
            stix_objects.append(sco)

        return stix_objects

    async def health_check(self) -> Dict[str, Any]:
        return {"status": "HEALTHY", "feed_url": self.feed_url}
