"""VY-PAM gateway daemon (plan phase 8a - the node side of the data plane).

A stdlib-only worker process that:

- authenticates to the API with its node token (`vypam-gwn1.<id>.<secret>`)
  and heartbeats liveness + capacity;
- polls its work queue and, for each pending session, fetches the one-shot
  connect args (the vault credential travels exactly here, once), performs
  the real guacd handshake (`select` -> `args` -> `connect` -> `ready`,
  see `guacd.py`) and streams the connection;
- records what guacd sends: the native instruction stream, gzip-compressed
  and AES-256-GCM encrypted per segment under the per-recording data key
  (the same wire form the vault secrets use), sealed to disk and reported
  by SHA-256 - the bytes never touch the database;
- honors control without any inbound port: `pause` stops reading and
  acking (TCP backpressure stalls guacd's output), `terminate` closes the
  connection and reports the end.

Run:
    python gateway_daemon.py --api http://127.0.0.1:5000 \
        --token vypam-gwn1.<id>.<secret> [--storage DIR] [--poll 2.0]

`--storage` must point at the server's recording storage root
(RECORDING_STORAGE_DIR) so the API can read the sealed segments back.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

import guacd  # noqa: E402

WIRE_VERSION = 1
ALGORITHM = "AES-256-GCM"
SEGMENT_NONCE_BYTES = 12
GUAC_SYNC_EVERY_SECONDS = 5.0


class DaemonError(RuntimeError):
    pass


class ApiClient:
    """The daemon's view of the VY-PAM API: node token, JSON in/out."""

    def __init__(self, base_url: str, token: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        scheme = urllib.parse.urlsplit(self.base_url).scheme.lower()
        if scheme not in ("http", "https"):
            # Fail fast at startup: a file:/custom scheme here would make the
            # daemon read local paths as if they were the control plane.
            raise DaemonError(
                f"control-plane URL scheme {scheme!r} refused - http(s) only"
            )
        self.token = token
        self.timeout = timeout

    def call(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v1{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("Content-Type", "application/json")
        try:
            # scheme of base_url is validated http(s)-only at ApiClient init
            with urllib.request.urlopen(  # nosec B310
                request, timeout=timeout or self.timeout
            ) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise DaemonError(
                f"{method} {path} -> HTTP {exc.code}: {detail[:400]}"
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise DaemonError(f"{method} {path} failed: {exc}") from exc
        if not body:
            return {}
        try:
            parsed = json.loads(body.decode("utf-8"))
        except ValueError as exc:
            raise DaemonError(f"{method} {path} returned non-JSON") from exc
        if not isinstance(parsed, dict):
            raise DaemonError(f"{method} {path} returned a non-object")
        return parsed


def seal_segment(
    data_key: bytes, plaintext: bytes, gateway_session_id: int, seq: int
) -> bytes:
    """gzip -> AES-256-GCM under the per-recording key, in the vault's
    wire form: {'v', 'alg', 'nonce', 'ct'} (AAD binds it to gws + seq)."""
    nonce = os.urandom(SEGMENT_NONCE_BYTES)
    aad = f"recording_segment:{gateway_session_id}:{seq}".encode("utf-8")
    ciphertext = AESGCM(data_key).encrypt(nonce, gzip.compress(plaintext), aad)
    wire = {
        "v": WIRE_VERSION,
        "alg": ALGORITHM,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(wire).encode("utf-8")


class SessionWorker(threading.Thread):
    """One gateway session: handshake, stream, record, honor control."""

    def __init__(
        self,
        api: ApiClient,
        storage_root: str,
        work: Dict[str, Any],
        connect: Dict[str, Any],
        stop_event: threading.Event,
    ):
        super().__init__(daemon=True, name=f"gws-{work['gateway_session_id']}")
        self.api = api
        self.storage_root = storage_root
        self.work = work
        self.connect = connect
        self.stop_event = stop_event
        self.gws_id = work["gateway_session_id"]
        self.protocol = work["protocol"]
        self.record = bool(work.get("record"))
        self.recording = connect.get("recording")
        self.data_key = (
            bytes.fromhex(self.recording["data_key"]) if self.recording else None
        )
        self.client: Optional[guacd.GuacdClient] = None
        self.pause = threading.Event()
        self.terminated = threading.Event()
        self._buffer = bytearray()
        self._seq = 0
        self._segment_started = time.monotonic()
        self._sealed: List[Dict[str, Any]] = []
        self._last_sync = 0.0

    # -- reporting ------------------------------------------------------
    def _progress(
        self,
        *,
        state: Optional[str] = None,
        end_reason: Optional[str] = None,
        flush: bool = False,
    ) -> None:
        payload: Dict[str, Any] = {}
        if state is not None:
            payload["state"] = state
        if end_reason is not None:
            payload["end_reason"] = end_reason
        if flush:
            self._seal_segment(final=True)
        if self._sealed:
            payload["segments"] = self._sealed
            self._sealed = []
        if not payload:
            return
        try:
            self.api.call(
                "POST", f"/gateway/sessions/{self.gws_id}/progress", payload
            )
        except DaemonError as exc:
            # never lose the session record over a report; keep going and
            # let the next report (or the heartbeat) carry the truth
            print(f"[gws-{self.gws_id}] progress failed: {exc}", file=sys.stderr)

    # -- recording ------------------------------------------------------
    def _record(self, data: bytes) -> None:
        if self.record:
            self._buffer.extend(data)

    def _seal_segment(self, *, final: bool = False) -> None:
        if not self.record or self.data_key is None:
            return
        segment_seconds = int(self.recording.get("segment_seconds", 60))
        age = time.monotonic() - self._segment_started
        if not final and age < segment_seconds:
            return
        if not self._buffer:
            return
        plaintext = bytes(self._buffer)
        self._buffer = bytearray()
        self._segment_started = time.monotonic()
        seq = self._seq
        self._seq += 1
        blob = seal_segment(self.data_key, plaintext, self.gws_id, seq)
        subdir = self.recording.get("storage_subdir") or f"gws-{self.gws_id}"
        directory = os.path.join(self.storage_root, subdir)
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"seg-{seq:05d}.json")
        with open(path, "wb") as handle:
            handle.write(blob)
        self._sealed.append(
            {
                "seq": seq,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size_bytes": len(blob),
                "duration_seconds": round(age, 3),
                "tier": "hot",
            }
        )

    # -- the session itself --------------------------------------------
    def run(self) -> None:  # noqa: C901 - a session loop is naturally linear
        try:
            self._run()
        except (guacd.GuacdConnectionError, DaemonError) as exc:
            print(f"[gws-{self.gws_id}] ended: {exc}", file=sys.stderr)
            self._progress(state="ended", end_reason="connect-failed", flush=True)
        except (ConnectionError, TimeoutError) as exc:
            print(f"[gws-{self.gws_id}] stream closed: {exc}", file=sys.stderr)
            self._progress(state="ended", end_reason="client-disconnected", flush=True)
        except Exception as exc:  # noqa: BLE001 - the daemon must survive its workers
            print(f"[gws-{self.gws_id}] failed: {exc}", file=sys.stderr)
            self._progress(state="ended", end_reason="daemon-error", flush=True)
        finally:
            if self.client is not None:
                self.client.send_disconnect()
                self.client.close()

    def _run(self) -> None:
        self._progress(state="connecting")
        # the guacd endpoint is policy from the work item (settings), the
        # connection parameters are the injected credential + target
        client = guacd.GuacdClient(self._guacd_host(), self._guacd_port())
        params = dict(self.connect["params"])
        client.connect_protocol(self.protocol, params)
        self.client = client
        self._progress(state="active")

        while not self.stop_event.is_set() and not self.terminated.is_set():
            if self.pause.is_set():
                # paused: stop reading AND acking - TCP backpressure stalls
                # guacd's output queue, which freezes the target session
                time.sleep(0.2)
                continue
            try:
                opcode, args = client.read_instruction(timeout=1.0)
            except TimeoutError:
                # a quiet session still rolls segments on the wall clock:
                # the seal timer must never depend on traffic arriving, or
                # an idle target produces zero segments until disconnect
                self._seal_segment()
                self._progress()
                continue
            wire = guacd.encode_instruction(opcode, *args)
            self._record(wire)

            # flow control: a real client acks stream blobs and end, and
            # syncs on a timer - guacd paces its output on both
            if opcode == "blob" and args:
                client.send_ack(args[0])
            elif opcode == "end" and args:
                client.send_ack(args[0])
            now = time.monotonic()
            if now - self._last_sync >= GUAC_SYNC_EVERY_SECONDS:
                client.send_sync(int(now * 1000))
                self._last_sync = now
            self._seal_segment()
            # streamed upload: a sealed segment reaches the control plane
            # right away - the storage paper's segment rationale (streaming
            # upload, partial playback, crash recovery) dies if the ledger
            # only hears about segments at session end
            self._progress()

        reason = "terminated" if self.terminated.is_set() else "daemon-stopped"
        self._progress(state="ended", end_reason=reason, flush=True)

    def _guacd_host(self) -> str:
        return str(self.work.get("guacd", {}).get("host", "127.0.0.1"))

    def _guacd_port(self) -> int:
        return int(self.work.get("guacd", {}).get("port", guacd.DEFAULT_GUACD_PORT))


class GatewayDaemon:
    """The node's main loop: heartbeat, poll, dispatch, honor directives."""

    def __init__(
        self,
        api: ApiClient,
        node_id: int,
        storage_root: str,
        poll_seconds: float,
        version: str = "8a",
    ):
        self.api = api
        self.node_id = node_id
        self.storage_root = storage_root
        self.poll_seconds = poll_seconds
        self.version = version
        self.stop_event = threading.Event()
        self.workers: Dict[int, SessionWorker] = {}
        self.terminate_ids: List[int] = []

    def _heartbeat(self) -> None:
        reply = self.api.call(
            "POST",
            f"/gateway/nodes/{self.node_id}/heartbeat",
            {"capacity_active": len(self.workers), "version": self.version},
        )
        for gws_id in reply.get("terminate", []):
            self.terminate_ids.append(int(gws_id))

    def _dispatch(self) -> None:
        work = self.api.call("GET", f"/gateway/nodes/{self.node_id}/work")
        for item in work.get("pending", []):
            gws_id = int(item["gateway_session_id"])
            if gws_id in self.workers:
                continue
            try:
                connect = self.api.call(
                    "GET", f"/gateway/sessions/{gws_id}/connect-args"
                )
            except DaemonError as exc:
                print(f"[gws-{gws_id}] connect-args refused: {exc}", file=sys.stderr)
                continue
            worker = SessionWorker(
                self.api, self.storage_root, item, connect, self.stop_event
            )
            self.workers[gws_id] = worker
            worker.start()
        for item in work.get("live", []):
            gws_id = int(item["gateway_session_id"])
            worker = self.workers.get(gws_id)
            if worker is None:
                continue
            if item.get("control") == "pause":
                worker.pause.set()
            else:
                worker.pause.clear()
        for gws_id in self.terminate_ids:
            worker = self.workers.get(gws_id)
            if worker is not None:
                worker.terminated.set()
                worker.pause.clear()
        self.terminate_ids = []
        # forget finished workers
        for gws_id in [g for g, w in self.workers.items() if not w.is_alive()]:
            self.workers.pop(gws_id, None)

    def run(self) -> None:
        last_heartbeat = 0.0
        while not self.stop_event.is_set():
            now = time.monotonic()
            if now - last_heartbeat >= max(self.poll_seconds, 2.0):
                try:
                    self._heartbeat()
                    last_heartbeat = now
                except DaemonError as exc:
                    print(f"heartbeat failed: {exc}", file=sys.stderr)
            try:
                self._dispatch()
            except DaemonError as exc:
                print(f"work poll failed: {exc}", file=sys.stderr)
            self.stop_event.wait(self.poll_seconds)
        # graceful: terminate live workers and report each end
        for worker in list(self.workers.values()):
            worker.terminated.set()
            worker.pause.clear()
        for worker in list(self.workers.values()):
            worker.join(timeout=5.0)

    def stop(self, *_args: Any) -> None:
        self.stop_event.set()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="VY-PAM gateway daemon (8a)")
    parser.add_argument("--api", required=True, help="API base URL")
    parser.add_argument("--token", required=True, help="vypam-gwn1.<id>.<secret>")
    parser.add_argument(
        "--storage",
        default=os.getenv("RECORDING_STORAGE_DIR", "recordings"),
        help="Recording storage root (must match the server's)",
    )
    parser.add_argument("--poll", type=float, default=2.0)
    args = parser.parse_args(argv)

    parts = args.token.split(".")
    if len(parts) != 3 or not parts[1].isdigit():
        print("token must be vypam-gwn1.<id>.<secret>", file=sys.stderr)
        return 2
    node_id = int(parts[1])
    api = ApiClient(args.api, args.token)
    daemon = GatewayDaemon(api, node_id, args.storage, max(args.poll, 0.2))
    signal.signal(signal.SIGINT, daemon.stop)
    signal.signal(signal.SIGTERM, daemon.stop)
    print(
        f"gateway daemon up: node {node_id}, api {args.api}, "
        f"storage {args.storage}, protocol {guacd.PROTOCOL_VERSION}",
        flush=True,
    )
    daemon.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
