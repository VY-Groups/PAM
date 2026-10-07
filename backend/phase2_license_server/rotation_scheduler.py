"""Optional background scheduler for due rotations (architecture module 5).

Off unless `ROTATION_SCHEDULER=1`; the interval comes from
`ROTATION_SCHEDULER_INTERVAL_SECONDS` (default 300). The thread only ever
runs the same `service.run_rotations` pipeline an admin click runs — with
`trigger=scheduled` and failed items left alone (manual Retry owns those) —
so every scheduled rotation is a real, audited row, and a quiet clock
produces no events at all.
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


def run_due(app: Flask, *, actor: str = "scheduler") -> Dict[str, Any]:
    """One scheduler tick: end elapsed JIT windows first (release + rotate),
    then rotate what is genuinely due, right now."""
    from service import refresh_jit_requests, run_rotations

    with app.app_context():
        jit_expired = refresh_jit_requests()
        summary = run_rotations(
            {}, actor=actor, trigger="scheduled", include_failed=False
        )
        summary["jit_expired"] = jit_expired
        if jit_expired:
            logger.info("jit expiry: %d grant(s) ended and rotated", jit_expired)
        if summary["rotated"]:
            logger.info(
                "scheduled rotation: %d credential(s), %d dependent(s)",
                len(summary["rotated"]),
                summary["dependents_rotated"],
            )
        return summary


def start(app: Flask, interval_seconds: int) -> None:
    """Start the daemon thread once per process."""
    global _STARTED
    with _START_LOCK:
        if _STARTED:
            return
        _STARTED = True

    interval = max(5, int(interval_seconds))

    def loop() -> None:
        while True:
            time.sleep(interval)
            try:
                run_due(app)
            except Exception:  # pragma: no cover - defensive loop guard
                logger.exception("scheduled rotation tick failed")

    threading.Thread(target=loop, daemon=True, name="rotation-scheduler").start()
    logger.info("rotation scheduler started (every %ss)", interval)
