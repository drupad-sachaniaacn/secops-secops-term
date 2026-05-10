"""Alert deduplication and grouping.

Per brief v3 §6.3:

> Dedupe by ``dedupe_key``. Group near-duplicates by ``(title_signature,
> primary_entity)`` within a sliding 1-hour window — present as a single
> card with a count.

Two passes:

1. :func:`dedupe_alerts` — strict drop of duplicates by ``dedupe_key``.
   First-seen wins (newest input order is preserved when callers pre-sort).
2. :func:`group_alerts` — bucket post-dedupe alerts by
   ``(title_signature, primary_entity)`` within a 1-hour sliding window.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from secops_term.alerts.normalize import title_signature
from secops_term.alerts.types import Alert, AlertGroup

DEFAULT_GROUP_WINDOW = timedelta(hours=1)


def dedupe_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    """Drop duplicates by ``dedupe_key``. Preserves first-seen order."""
    out: list[Alert] = []
    seen: set[str] = set()
    for a in alerts:
        if a.dedupe_key in seen:
            continue
        seen.add(a.dedupe_key)
        out.append(a)
    return out


def group_alerts(
    alerts: Iterable[Alert],
    *,
    window: timedelta = DEFAULT_GROUP_WINDOW,
) -> list[AlertGroup]:
    """Group alerts by ``(title_signature, primary_entity)`` within ``window``.

    Returns one :class:`AlertGroup` per cluster; the ``representative`` is
    the most recent alert in the cluster, ``members`` is every alert
    (including the representative) ordered newest-first.
    """
    # Stable sort newest-first so groups grow newest-to-oldest.
    sorted_alerts = sorted(alerts, key=lambda a: a.detected_at, reverse=True)
    buckets: list[list[Alert]] = []
    bucket_keys: list[tuple[str, Any]] = []

    for a in sorted_alerts:
        sig = title_signature(a.title)
        primary = a.primary_entity()
        primary_repr = (primary.type, primary.value) if primary is not None else None
        key = (sig, primary_repr)

        placed = False
        for i, existing_key in enumerate(bucket_keys):
            if existing_key != key:
                continue
            # Within-window check against the bucket's representative
            # (the bucket's first/newest alert).
            rep_time = buckets[i][0].detected_at
            if rep_time - a.detected_at <= window:
                buckets[i].append(a)
                placed = True
                break
        if not placed:
            buckets.append([a])
            bucket_keys.append(key)

    return [AlertGroup(representative=members[0], members=tuple(members)) for members in buckets]


__all__ = ["DEFAULT_GROUP_WINDOW", "dedupe_alerts", "group_alerts"]
