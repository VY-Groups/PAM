"""Optional automatic-failover monitor for HA / DC / DR (architecture 18).

Off unless `CLUSTER_MONITOR=1`; the interval comes from
`CLUSTER_MONITOR_INTERVAL_SECONDS` (default 60, floor 5). The thread only
ever runs the same `service.run_cluster_monitor` an admin runs by calling
`POST /api/v1/cluster/monitor/tick` - with the actor `cluster-monitor` -
so every promotion is a real, audited row with the probe failures that
caused it in `detail`, and a quiet clock (this node active, or a healthy
passive) produces no events at all.

Honest scope: a single-binary node cannot move the load balancer for you.
What this monitor really does is detect, on real probes, that every
registered active peer is gone, and promote *this* node with those
failures as the recorded reason - the runbook then cuts traffic over.
Automatic failover of the node's own role, not of someone else's DNS.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict

from flask import Flask

logger = logging.getLogger(__name__)

_STARTED = False
_START_LOCK = threading.Lock()


def tick(app: Flask, *, actor: str = "cluster-monitor") -> Dict[str, Any]:
    """One monitor tick inside the app context: the same code path an
    admin's `POST /cluster/monitor/tick` runs."""
    from service import run_cluster_monitor

    with app.app_context():
        return run_cluster_monitor(actor=actor)


def _loop(app: Flask, interval: int) -> None:
    while True:
        try:
            outcome = tick(app)
            if outcome.get("promoted"):
                logger.warning(
                    "Cluster monitor: automatic promotion after %s",
                    outcome.get("reason", "consecutive failed probes"),
                )
        except Exception:  # pragma: no cover - only when the DB is down
            logger.exception("Cluster monitor tick failed")
        time.sleep(interval)


def start(app: Flask, interval: int) -> None:
    """Start the monitor thread once (idempotent, like the rotation
    scheduler). Tests never enable it - they call `run_cluster_monitor`
    directly so the clock never decides anything."""
    global _STARTED
    with _START_LOCK:
        if _STARTED:
            return
        interval = max(5, interval)
        thread = threading.Thread(
            target=_loop,
            args=(app, interval),
            name="cluster-monitor",
            daemon=True,
        )
        thread.start()
        _STARTED = True
        logger.info("Cluster monitor started (every %ds)", interval)
