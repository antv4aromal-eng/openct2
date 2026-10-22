"""
Deterministic STIX 2.1 UUIDv5 Generator
Parity with OASIS STIX 2.1 Spec (Section 2.9) and OpenCTI Canonical Key Generation.
"""

import uuid
import json
from typing import Any, Dict, Optional, Union

# OASIS STIX 2.1 Standard Namespace UUID
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fedf7a7a527b")

# OpenCTI / OASIS Standard Canonical Key Mappings
CANONICAL_KEY_EXTRACTORS = {
    "ipv4-addr": lambda v: v.get("value", "").strip() if isinstance(v, dict) else str(v).strip(),
    "ipv6-addr": lambda v: v.get("value", "").strip().lower() if isinstance(v, dict) else str(v).strip().lower(),
    "domain-name": lambda v: v.get("value", "").strip().lower() if isinstance(v, dict) else str(v).strip().lower(),
    "url": lambda v: v.get("value", "").strip() if isinstance(v, dict) else str(v).strip(),
    "email-addr": lambda v: v.get("value", "").strip().lower() if isinstance(v, dict) else str(v).strip().lower(),
    "vulnerability": lambda v: (
        (v.get("name") or v.get("cve_id", "")).strip().upper()
        if isinstance(v, dict)
        else str(v).strip().upper()
    ),
    "attack-pattern": lambda v: (
        v.get("name", "").strip().lower()
        if isinstance(v, dict)
        else str(v).strip().lower()
    ),
    "malware": lambda v: (
        v.get("name", "").strip().lower()
        if isinstance(v, dict)
        else str(v).strip().lower()
    ),
    "intrusion-set": lambda v: (
        v.get("name", "").strip().lower()
        if isinstance(v, dict)
        else str(v).strip().lower()
    ),
    "threat-actor": lambda v: (
        v.get("name", "").strip().lower()
        if isinstance(v, dict)
        else str(v).strip().lower()
    ),
    "tool": lambda v: (
        v.get("name", "").strip().lower()
        if isinstance(v, dict)
        else str(v).strip().lower()
    ),
    "indicator": lambda v: (
        v.get("pattern", "").strip()
        if isinstance(v, dict)
        else str(v).strip()
    ),
    "identity": lambda v: (
        v.get("name", "").strip().lower()
        if isinstance(v, dict)
        else str(v).strip().lower()
    ),
    "infrastructure": lambda v: (
        v.get("name", "").strip().lower()
        if isinstance(v, dict)
        else str(v).strip().lower()
    ),
    "location": lambda v: (
        (v.get("name") or v.get("country", "")).strip().lower()
        if isinstance(v, dict)
        else str(v).strip().lower()
    ),
}


def generate_deterministic_stix_id(
    stix_type: str,
    canonical_input: Union[str, Dict[str, Any]],
    namespace: uuid.UUID = STIX_NAMESPACE
) -> str:
    """
    Generates a deterministic STIX 2.1 identifier formatted as:
    `{stix_type}--{uuidv5}`
    
    Args:
        stix_type: STIX object type (e.g. 'indicator', 'malware', 'ipv4-addr', 'relationship')
        canonical_input: Canonical string value or dictionary containing defining attributes
        namespace: UUID namespace for UUIDv5 generation (defaults to STIX standard namespace)
        
    Returns:
        Deterministic STIX 2.1 ID string
    """
    clean_type = stix_type.lower().strip()

    if isinstance(canonical_input, dict):
        extractor = CANONICAL_KEY_EXTRACTORS.get(clean_type)
        if extractor:
            seed_string = extractor(canonical_input)
        else:
            # Deterministic JSON serialization with sorted keys
            seed_string = json.dumps(canonical_input, sort_keys=True, separators=(",", ":"))
    else:
        seed_string = str(canonical_input).strip()
        if clean_type in ("ipv4-addr", "url"):
            seed_string = seed_string
        elif clean_type in ("vulnerability",):
            seed_string = seed_string.upper()
        else:
            seed_string = seed_string.lower()

    # Prepend type seed to ensure cross-type uniqueness
    namespaced_seed = f"{clean_type}::{seed_string}"
    generated_uuid = uuid.uuid5(namespace, namespaced_seed)
    return f"{clean_type}--{generated_uuid}"


def generate_relationship_stix_id(
    relationship_type: str,
    source_ref: str,
    target_ref: str,
    namespace: uuid.UUID = STIX_NAMESPACE
) -> str:
    """
    Generates a deterministic STIX 2.1 identifier for Relationship (SRO) objects.
    Ensures identical relationships between source and target yield identical IDs.
    """
    rel_type = relationship_type.strip().lower()
    s_ref = source_ref.strip()
    t_ref = target_ref.strip()
    canonical = f"{rel_type}::{s_ref}::{t_ref}"
    return generate_deterministic_stix_id("relationship", canonical, namespace=namespace)
