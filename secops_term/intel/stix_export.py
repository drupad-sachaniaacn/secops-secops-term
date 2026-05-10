"""STIX 2.1 bundle export for IOCs from the local store.

Per brief v3 §6.3. Converts :class:`~secops_term.intel.ioc.IOC` objects
(read from the SQLite store) into STIX 2.1 objects and packages them in a
STIX bundle.

IOC type → STIX object mapping
--------------------------------

===========  ============================  ============================
IOC type     STIX object type              Key field(s)
===========  ============================  ============================
``ipv4``     ``ipv4-addr`` (SCO)           ``value``
``ipv6``     ``ipv6-addr`` (SCO)           ``value``
``domain``   ``domain-name`` (SCO)         ``value``
``url``      ``url`` (SCO)                 ``value``
``sha256``   ``file`` (SCO)                ``hashes["SHA-256"]``
``sha1``     ``file`` (SCO)                ``hashes["SHA-1"]``
``md5``      ``file`` (SCO)                ``hashes["MD5"]``
``email``    ``email-addr`` (SCO)          ``value``
``cve``      ``vulnerability`` (SDO)       ``name`` + external reference
===========  ============================  ============================

ID generation
-------------
SCO IDs use :func:`uuid.uuid5` with the STIX 2.1 SCO deterministic namespace
``00abedb4-aa42-466c-9c01-fed23315a9b7`` and the seed ``"{type}:{value}"``.
This makes the same IOC always produce the same STIX ID across exports, so
consumers can merge overlapping bundles without creating duplicates.

SDO IDs (``vulnerability``) use the same namespace seeded with
``"vulnerability:{cve_id}"``.

Bundle IDs use a fresh random UUIDv4 on each export.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from secops_term.intel.ioc import IOC

# STIX 2.1 deterministic namespace for SCOs.
# Ref: STIX 2.1 spec §2.9
_STIX_SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
_STIX_SPEC_VERSION = "2.1"

# Mapping from our IOC type to (stix_object_type, value_field).
# Hash types are special-cased in _ioc_to_stix_object.
_SCO_MAP: dict[str, tuple[str, str]] = {
    "ipv4": ("ipv4-addr", "value"),
    "ipv6": ("ipv6-addr", "value"),
    "domain": ("domain-name", "value"),
    "url": ("url", "value"),
    "email": ("email-addr", "value"),
}
_HASH_KEY_MAP: dict[str, str] = {
    "sha256": "SHA-256",
    "sha1": "SHA-1",
    "md5": "MD5",
}
_NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail"


def stix_id_for(obj_type: str, seed: str) -> str:
    """Return a deterministic STIX ID for *obj_type* seeded by *seed*.

    Example::

        stix_id_for("ipv4-addr", "ipv4:1.2.3.4")
        # → "ipv4-addr--<uuid5>"
    """
    uid = uuid.uuid5(_STIX_SCO_NAMESPACE, seed)
    return f"{obj_type}--{uid}"


def ioc_to_stix_object(ioc: IOC) -> dict[str, Any] | None:
    """Convert one :class:`~secops_term.intel.ioc.IOC` to a STIX 2.1 object dict.

    Returns ``None`` for IOC types that have no STIX mapping (currently none —
    all nine canonical types are handled, but the guard is here for safety if
    new types are added later).
    """
    if ioc.type in _SCO_MAP:
        stix_type, field = _SCO_MAP[ioc.type]
        return {
            "type": stix_type,
            "spec_version": _STIX_SPEC_VERSION,
            "id": stix_id_for(stix_type, f"{ioc.type}:{ioc.value}"),
            field: ioc.value,
        }

    if ioc.type in _HASH_KEY_MAP:
        hash_key = _HASH_KEY_MAP[ioc.type]
        return {
            "type": "file",
            "spec_version": _STIX_SPEC_VERSION,
            "id": stix_id_for("file", f"{ioc.type}:{ioc.value}"),
            "hashes": {hash_key: ioc.value},
        }

    if ioc.type == "cve":
        ts = _stix_timestamp(ioc.first_seen)
        ts_mod = _stix_timestamp(ioc.last_seen)
        return {
            "type": "vulnerability",
            "spec_version": _STIX_SPEC_VERSION,
            "id": stix_id_for("vulnerability", f"vulnerability:{ioc.value}"),
            "name": ioc.value,
            "created": ts,
            "modified": ts_mod,
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": ioc.value,
                    "url": f"{_NVD_DETAIL_URL}/{ioc.value}",
                }
            ],
        }

    return None


def export_bundle(iocs: Sequence[IOC]) -> dict[str, Any]:
    """Build a STIX 2.1 bundle dict from *iocs*.

    Duplicate STIX IDs are collapsed to the first occurrence (same IOC value
    appearing more than once in the input produces only one STIX object).
    The bundle ID is a fresh random UUIDv4 on each call.
    """
    seen_ids: set[str] = set()
    objects: list[dict[str, Any]] = []
    for ioc in iocs:
        obj = ioc_to_stix_object(ioc)
        if obj is None:
            continue
        obj_id = obj["id"]
        if obj_id in seen_ids:
            continue
        seen_ids.add(obj_id)
        objects.append(obj)
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def export_bundle_json(iocs: Sequence[IOC], *, indent: int = 2) -> str:
    """Return the STIX 2.1 bundle as a JSON string."""
    return json.dumps(export_bundle(iocs), indent=indent, ensure_ascii=False)


# Helpers


def _stix_timestamp(dt: datetime) -> str:
    """Format a datetime as a STIX 2.1 timestamp string (UTC, millisecond precision)."""
    utc = dt.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


__all__ = [
    "export_bundle",
    "export_bundle_json",
    "ioc_to_stix_object",
    "stix_id_for",
]
