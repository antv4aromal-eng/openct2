"""
Base Connector Framework for OpenCTI ATIP Platform
Provides standard lifecycle management, rate limiting, STIX bundle dispatching, and health checking.
"""

import abc
import asyncio
import json
import os
import signal
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import structlog
from pydantic import BaseModel, Field
from .stix_id import generate_deterministic_stix_id, generate_relationship_stix_id
from .rate_limiter import RedisTokenBucketRateLimiter

logger = structlog.get_logger(__name__)


class ConnectorConfig(BaseModel):
    connector_id: str
    connector_name: str
    connector_type: str  # EXTERNAL_IMPORT | INTERNAL_ENRICHMENT | INTERNAL_ANALYSIS
    kafka_brokers: str = Field(default_factory=lambda: os.getenv("KAFKA_BROKERS", "localhost:9092"))
    kafka_raw_topic: str = Field(default="atip.ingest.raw")
    kafka_enrichment_topic: str = Field(default="atip.enrichment.requests")
    redis_url: str = Field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    poll_interval_seconds: int = 300
    confidence_level: int = 80
    tlp_marking: str = "TLP:CLEAR"
    rate_limit_capacity: float = 10.0
    rate_limit_refill_per_sec: float = 1.0


class STIXBundleEnvelope(BaseModel):
    id: str
    type: str = "bundle"
    spec_version: str = "2.1"
    objects: List[Dict[str, Any]] = Field(default_factory=list)
    connector_metadata: Dict[str, Any] = Field(default_factory=dict)


class BaseConnector(abc.ABC):
    """
    Abstract base connector for all ATIP ingest, enrichment, and analysis agents.
    """

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.running = False
        self.redis_client = None
        self.kafka_producer = None
        self.rate_limiter: Optional[RedisTokenBucketRateLimiter] = None
        self._shutdown_event = asyncio.Event()

    async def initialize(self) -> None:
        """Initialize messaging, rate limiter, and database connections."""
        logger.info(
            "initializing_connector",
            connector_id=self.config.connector_id,
            connector_type=self.config.connector_type
        )
        try:
            import redis.asyncio as aioredis
            self.redis_client = aioredis.from_url(self.config.redis_url)
            await self.redis_client.ping()
        except Exception as e:
            logger.warning("redis_connect_failed_using_mock", error=str(e))
            self.redis_client = None

        self.rate_limiter = RedisTokenBucketRateLimiter(
            redis_client=self.redis_client,
            key=f"ratelimit:{self.config.connector_id}",
            capacity=self.config.rate_limit_capacity,
            refill_rate=self.config.rate_limit_refill_per_sec,
            auto_wait=True
        )

        try:
            from aiokafka import AIOKafkaProducer
            self.kafka_producer = AIOKafkaProducer(
                bootstrap_servers=self.config.kafka_brokers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8")
            )
            await self.kafka_producer.start()
            logger.info("kafka_producer_connected", brokers=self.config.kafka_brokers)
        except Exception as e:
            logger.warning("kafka_producer_failed_using_mock", error=str(e))
            self.kafka_producer = None

    async def shutdown(self) -> None:
        """Gracefully release connections and stop loops."""
        logger.info("shutting_down_connector", connector_id=self.config.connector_id)
        self.running = False
        self._shutdown_event.set()

        if self.kafka_producer:
            try:
                await self.kafka_producer.stop()
            except Exception as e:
                logger.error("error_closing_kafka", error=str(e))

        if self.redis_client:
            try:
                await self.redis_client.close()
            except Exception as e:
                logger.error("error_closing_redis", error=str(e))

    def make_bundle(self, stix_objects: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Wrap STIX 2.1 objects in a standard STIX 2.1 bundle with audit metadata."""
        bundle_id = generate_deterministic_stix_id(
            "bundle",
            f"{self.config.connector_id}::{datetime.now(timezone.utc).isoformat()}::{len(stix_objects)}"
        )
        return {
            "id": bundle_id,
            "type": "bundle",
            "spec_version": "2.1",
            "objects": stix_objects,
            "x_atip_connector": {
                "connector_id": self.config.connector_id,
                "connector_name": self.config.connector_name,
                "confidence": self.config.confidence_level,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }

    async def publish_bundle(self, bundle: Dict[str, Any], topic: Optional[str] = None) -> None:
        """Publish STIX bundle to the designated Kafka topic or fallback to stdout log."""
        target_topic = topic or self.config.kafka_raw_topic
        if self.rate_limiter:
            await self.rate_limiter.acquire()

        if self.kafka_producer:
            try:
                await self.kafka_producer.send_and_wait(target_topic, bundle)
                logger.info(
                    "published_bundle",
                    bundle_id=bundle.get("id"),
                    object_count=len(bundle.get("objects", [])),
                    topic=target_topic
                )
                return
            except Exception as e:
                logger.error("kafka_publish_failed", error=str(e))

        # Fallback stdout logging in standalone / mock testing mode
        logger.info(
            "standalone_bundle_dispatched",
            bundle_id=bundle.get("id"),
            objects_count=len(bundle.get("objects", [])),
            topic=target_topic
        )

    @abc.abstractmethod
    async def run(self) -> None:
        """Main execution lifecycle loop."""
        pass

    @abc.abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Validate operational state and external connectivity."""
        pass


class ExternalImportConnector(BaseConnector):
    """Specialized connector for scheduled external API polling."""

    @abc.abstractmethod
    async def collect(self) -> List[Dict[str, Any]]:
        """Fetch and transform external data into STIX 2.1 objects."""
        pass

    async def run(self) -> None:
        await self.initialize()
        self.running = True

        logger.info("external_import_connector_started", interval=self.config.poll_interval_seconds)
        while self.running and not self._shutdown_event.is_set():
            try:
                logger.info("running_collection_cycle", connector=self.config.connector_name)
                stix_objects = await self.collect()
                if stix_objects:
                    bundle = self.make_bundle(stix_objects)
                    await self.publish_bundle(bundle)
                logger.info("cycle_completed", objects_collected=len(stix_objects))
            except Exception as e:
                logger.error("collection_error", error=str(e), exc_info=True)

            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=float(self.config.poll_interval_seconds)
                )
            except asyncio.TimeoutError:
                pass


class InternalEnrichmentConnector(BaseConnector):
    """Specialized connector for reactive observable enrichment requests."""

    @abc.abstractmethod
    async def enrich_entity(self, entity: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enrich a target entity and return new SDOs/SCOs/SROs."""
        pass

    async def run(self) -> None:
        await self.initialize()
        self.running = True
        logger.info("internal_enrichment_connector_started", topic=self.config.kafka_enrichment_topic)

        # In production, consume Kafka enrichment requests
        while self.running and not self._shutdown_event.is_set():
            await asyncio.sleep(1)


class InternalAnalysisConnector(BaseConnector):
    """Specialized connector for unstructured defanging and Sigma rule synthesis."""

    @abc.abstractmethod
    async def analyze(self, raw_input: str) -> Dict[str, Any]:
        """Process unstructured threat text into structured STIX 2.1 + detection rules."""
        pass

    async def run(self) -> None:
        await self.initialize()
        self.running = True
        logger.info("internal_analysis_connector_started")
        while self.running and not self._shutdown_event.is_set():
            await asyncio.sleep(1)
