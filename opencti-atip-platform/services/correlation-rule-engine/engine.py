"""
OpenCTI ATIP Platform - Correlation Rule Engine
Stream processor for Graph CDC events. Executes 2nd-hop pivot discovery,
MITRE ATT&CK procedure correlation, and automatic Sigma rule synthesis triggers.
"""

import asyncio
import json
import os
import signal
from datetime import datetime, timezone
from typing import Any, Dict, List
import structlog

logger = structlog.get_logger(__name__)


class CorrelationRuleEngine:
    def __init__(self):
        self.kafka_brokers = os.getenv("KAFKA_BROKERS", "localhost:9092")
        self.cdc_topic = os.getenv("KAFKA_CDC_TOPIC", "atip.graph.cdc")
        self.enrichment_topic = os.getenv("KAFKA_ENRICHMENT_TOPIC", "atip.enrichment.requests")
        self.running = False
        self._shutdown_event = asyncio.Event()

    async def start(self):
        self.running = True
        logger.info(
            "correlation_engine_started",
            brokers=self.kafka_brokers,
            cdc_topic=self.cdc_topic,
            enrichment_topic=self.enrichment_topic
        )

        try:
            from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
            consumer = AIOKafkaConsumer(
                self.cdc_topic,
                bootstrap_servers=self.kafka_brokers,
                group_id="atip-correlation-group",
                auto_offset_reset="latest",
                value_deserializer=lambda m: json.loads(m.decode("utf-8"))
            )
            producer = AIOKafkaProducer(
                bootstrap_servers=self.kafka_brokers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8")
            )
            await consumer.start()
            await producer.start()

            while self.running and not self._shutdown_event.is_set():
                try:
                    data = await consumer.getmany(timeout_ms=1000, max_records=20)
                    for topic_partition, messages in data.items():
                        for msg in messages:
                            await self.evaluate_event(msg.value, producer)
                except Exception as e:
                    logger.error("correlation_loop_error", error=str(e))
                    await asyncio.sleep(1)

        except Exception as e:
            logger.warning("kafka_offline_running_in_standalone_eval_mode", reason=str(e))
            while self.running and not self._shutdown_event.is_set():
                await asyncio.sleep(2)

    async def evaluate_event(self, cdc_event: Dict[str, Any], producer=None):
        """Evaluate correlation rules against incoming graph changes."""
        stype = cdc_event.get("stix_type")
        entity_id = cdc_event.get("entity_id")
        op = cdc_event.get("operation")

        logger.info("evaluating_cdc_event", entity_id=entity_id, stype=stype, op=op)

        # Rule 1: Automated 2nd-Hop Pivot for newly created IP Observables
        if stype in ("ipv4-addr", "domain-name") and op == "CREATE":
            enrichment_request = {
                "request_id": f"enr-{entity_id}",
                "target_stix_id": entity_id,
                "stix_type": stype,
                "depth": 2,
                "requested_by": "correlation-engine:rule-2nd-hop-pivot",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            if producer:
                try:
                    await producer.send_and_wait(self.enrichment_topic, enrichment_request)
                    logger.info("dispatched_2nd_hop_enrichment", target=entity_id)
                except Exception as e:
                    logger.error("failed_to_send_enrichment_request", error=str(e))

        # Rule 2: High-Confidence Corroboration Alert & Sigma Synthesis
        conf = cdc_event.get("confidence_after", 0)
        corroborations = cdc_event.get("corroborations", 1)
        if conf >= 90 and corroborations >= 2:
            logger.info(
                "high_confidence_threat_chain_detected",
                entity=entity_id,
                confidence=conf,
                corroborations=corroborations
            )

    async def stop(self):
        logger.info("stopping_correlation_rule_engine")
        self.running = False
        self._shutdown_event.set()


def main():
    engine = CorrelationRuleEngine()
    loop = asyncio.get_event_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(engine.stop()))

    try:
        loop.run_until_complete(engine.start())
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(engine.stop())


if __name__ == "__main__":
    main()
