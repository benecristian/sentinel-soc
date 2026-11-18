"""Sliding-window primitives for rule evaluation.

Window semantics (Section 10.2 of DEVELOPMENT_PLAN.md):
* Events are ordered by `event.timestamp` (event time, not ingest time).
* A window `[first, last]` spans `<= time_window_seconds` **inclusive**:
  `(last.timestamp - first.timestamp).total_seconds() <= time_window_seconds`.
  For example, with a 300 s window, events spanning 300.0 s qualify; 300.001 s
  do not.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Hashable, Sequence
from datetime import timedelta

from app.domain.events import NormalizedEvent


def group_events_by[K: Hashable](
    events: Sequence[NormalizedEvent], key_fn: Callable[[NormalizedEvent], K | None]
) -> dict[K, list[NormalizedEvent]]:
    """Group events by `key_fn` (skipping None keys) and sort each group by timestamp."""
    groups: dict[K, list[NormalizedEvent]] = defaultdict(list)
    for ev in events:
        key = key_fn(ev)
        if key is not None:
            groups[key].append(ev)
    for bucket in groups.values():
        bucket.sort(key=lambda e: (e.timestamp, str(e.event_id)))
    return groups


def maximal_window(
    sorted_events: Sequence[NormalizedEvent],
    window_seconds: int,
    qualifies: Callable[[Sequence[NormalizedEvent]], bool],
) -> list[NormalizedEvent] | None:
    """Find a qualifying window and expand it to include all events in the burst.

    Uses a two-pointer sliding window `[left, right]` where
    `sorted_events[right].timestamp - sorted_events[left].timestamp <= window_seconds`.
    Once a qualifying `[left, right]` is found, `right` is advanced as far as
    possible while keeping the span within `window_seconds` from `left`, or if
    subsequent events continue the burst within `window_seconds` of the start of
    the qualifying window. Returns the matched slice, or None if no window
    qualifies.
    """
    if not sorted_events:
        return None
    max_delta = timedelta(seconds=window_seconds)
    n = len(sorted_events)
    left = 0

    for right in range(n):
        while sorted_events[right].timestamp - sorted_events[left].timestamp > max_delta:
            left += 1
        candidate = sorted_events[left : right + 1]
        if qualifies(candidate):
            # Greedily include the rest of the events that still fall within
            # `window_seconds` of `sorted_events[left]`.
            end = right
            while (
                end + 1 < n
                and sorted_events[end + 1].timestamp - sorted_events[left].timestamp <= max_delta
            ):
                end += 1
            return list(sorted_events[left : end + 1])

    return None
