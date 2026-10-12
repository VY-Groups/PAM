"""guacd wire protocol (Apache Guacamole) - codec, parser, client.

Every framing rule in this module is taken from guacamole-server's own
sources (Apache-2.0), not reconstructed from memory:

- each element is written as ``"<character-length>.<content>"``, elements
  are joined with ``,`` and an instruction ends with ``;``
  (libguac/protocol.c ``__guac_socket_write_length_string`` and
  libguac/parser.c ``guac_parser_append``);
- element lengths count UTF-8 *characters*, not bytes
  (``guac_utf8_strlen``);
- parser limits: 8192 characters per instruction, 5 length digits, 128
  elements including the opcode (libguac/guacamole/parser-constants.h);
- the handshake is ``select`` -> ``args`` (protocol version first, then
  the parameter names the plugin needs) -> ``connect`` (the version
  echoed, then the values in that exact order) -> ``ready`` (the
  connection id) (guacd/connection.c ``guacd_route_connection`` +
  libguac/user-handshake.c ``guac_user_handle_connection``);
- on a bad handshake guacd answers ``error`` (message, status);
- blob payloads are capped at 6048 bytes per instruction
  (protocol-constants.h ``GUAC_PROTOCOL_BLOB_MAX_LENGTH``).

The module is stdlib-only and used by the gateway daemon to hold a real
guacd connection, and by the tests' stub guacd to speak the same bytes.
"""

from __future__ import annotations

import socket
import time
from typing import Dict, List, Optional, Sequence, Tuple

# libguac/guacamole/protocol-constants.h + parser-constants.h
PROTOCOL_VERSION = "VERSION_1_5_0"
MAX_INSTRUCTION_CHARS = 8192
MAX_LENGTH_DIGITS = 5
MAX_ELEMENTS = 128
BLOB_MAX_BYTES = 6048
DEFAULT_GUACD_PORT = 4822

# guacd's own parser holds 32768 bytes of instruction buffer
# (libguac/guacamole/parser.h __instructionbuf)
_MAX_BUFFER_BYTES = 32768


class GuacdProtocolError(Exception):
    """The bytes on the wire are not valid guacd protocol."""


class GuacdConnectionError(Exception):
    """guacd refused or failed the connection (the ``error`` opcode)."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


def _element(value: str) -> str:
    """One length-prefixed element: ``<charlen>.<content>``."""
    if not isinstance(value, str):
        raise GuacdProtocolError(f"Protocol element must be str, got {type(value)}")
    if "\n" in value or "\r" in value:
        raise GuacdProtocolError("Protocol element must not contain newlines")
    return f"{len(value)}.{value}"


def encode_instruction(opcode: str, *args: str) -> bytes:
    """Encode one instruction exactly the way libguac writes it, e.g.
    ``encode_instruction("select", "ssh")`` -> ``b"6.select,3.ssh;"``."""
    elements = (opcode,) + tuple(args)
    if len(elements) > MAX_ELEMENTS:
        raise GuacdProtocolError(
            f"Instruction has {len(elements)} elements (max {MAX_ELEMENTS})"
        )
    text = ",".join(_element(e) for e in elements) + ";"
    if len(text) > MAX_INSTRUCTION_CHARS:
        raise GuacdProtocolError(
            f"Instruction is {len(text)} characters (max {MAX_INSTRUCTION_CHARS})"
        )
    return text.encode("utf-8")


class GuacdParser:
    """Incremental guacd instruction parser, mirroring guac_parser_append's
    state machine: length digits -> '.' -> N characters -> ',' | ';'.

    feed() arbitrary byte chunks (including mid-instruction splits and
    multiple instructions per chunk); next_instruction() pops complete
    ``(opcode, args)`` pairs. Bound by the same limits libguac enforces.
    """

    def __init__(self) -> None:
        self._buffer = ""
        self._pending_bytes = 0  # bytes fed but not yet consumed
        import codecs

        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")

    def feed(self, data: bytes) -> None:
        """Append received bytes (a UTF-8 boundary may split a character)."""
        self._pending_bytes += len(data)
        if self._pending_bytes > _MAX_BUFFER_BYTES:
            raise GuacdProtocolError("Instruction buffer exhausted (no terminator)")
        try:
            self._buffer += self._decoder.decode(data)
        except UnicodeDecodeError as exc:
            raise GuacdProtocolError(f"Invalid UTF-8 on the wire: {exc}") from exc

    def next_instruction(self) -> Optional[Tuple[str, List[str]]]:
        """Pop one complete instruction, or None while more bytes are due."""
        buf = self._buffer
        pos = 0
        elements: List[str] = []

        while True:
            # --- parse the length prefix
            digits = ""
            while pos < len(buf) and buf[pos] in "0123456789" and len(digits) <= MAX_LENGTH_DIGITS:
                digits += buf[pos]
                pos += 1
            if not digits:
                # nothing (or garbage) before we ran out of buffer
                if pos < len(buf):
                    raise GuacdProtocolError(
                        f"Expected a length prefix at {buf[pos]!r}"
                    )
                return None
            if len(digits) > MAX_LENGTH_DIGITS:
                raise GuacdProtocolError("Length prefix exceeds max digits")
            length = int(digits)
            if length > MAX_INSTRUCTION_CHARS:
                raise GuacdProtocolError(
                    f"Element length {length} exceeds {MAX_INSTRUCTION_CHARS}"
                )

            # --- the '.' that opens the content
            if pos >= len(buf):
                return None
            if buf[pos] != ".":
                raise GuacdProtocolError(f"Expected '.' after length, got {buf[pos]!r}")
            pos += 1

            # --- exactly `length` characters of content
            if len(buf) - pos < length:
                return None
            elements.append(buf[pos : pos + length])
            pos += length
            if len(elements) > MAX_ELEMENTS:
                raise GuacdProtocolError(
                    f"Instruction exceeds {MAX_ELEMENTS} elements"
                )

            # --- ',' continues, ';' completes
            if pos >= len(buf):
                return None
            terminator = buf[pos]
            pos += 1
            if terminator == ",":
                continue
            if terminator == ";":
                break
            raise GuacdProtocolError(
                f"Element must end with ',' or ';', got {terminator!r}"
            )

        # commit: drop the consumed prefix of the buffer
        consumed_bytes = len(buf[:pos].encode("utf-8"))
        self._buffer = buf[pos:]
        self._pending_bytes = max(self._pending_bytes - consumed_bytes, 0)
        return elements[0], elements[1:]


class GuacdClient:
    """A guacd protocol client: performs the real handshake and streams
    instructions over a plain TCP socket."""

    def __init__(self, host: str, port: int = DEFAULT_GUACD_PORT, timeout: float = 15.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.connection_id: Optional[str] = None
        self.server_version: str = PROTOCOL_VERSION
        self._sock: Optional[socket.socket] = None
        self._parser = GuacdParser()

    # -- transport -----------------------------------------------------
    def open(self) -> None:
        if self._sock is not None:
            return
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        self._sock = sock

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self.connection_id = None

    def _send(self, data: bytes) -> None:
        if self._sock is None:
            raise GuacdProtocolError("Not connected to guacd")
        self._sock.sendall(data)

    def read_instruction(self, timeout: Optional[float] = None) -> Tuple[str, List[str]]:
        """Read one instruction, blocking up to `timeout` seconds."""
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        while True:
            instruction = self._parser.next_instruction()
            if instruction is not None:
                return instruction
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for a guacd instruction")
            if self._sock is None:
                raise GuacdProtocolError("Not connected to guacd")
            self._sock.settimeout(max(remaining, 0.05))
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout as exc:
                raise TimeoutError("Timed out waiting for guacd bytes") from exc
            if not chunk:
                raise ConnectionError("guacd closed the connection")
            self._parser.feed(chunk)

    # -- handshake -----------------------------------------------------
    def connect_protocol(self, protocol: str, params: Dict[str, str]) -> str:
        """Run the real handshake: select -> args -> connect -> ready.
        Returns guacd's connection id."""
        self.open()
        self._send(encode_instruction("select", protocol))

        opcode, args = self.read_instruction()
        if opcode == "error":
            raise GuacdConnectionError(
                args[0] if args else "guacd refused the protocol",
                int(args[1]) if len(args) > 1 and args[1].isdigit() else 0,
            )
        if opcode != "args" or not args:
            raise GuacdProtocolError(
                f"Expected 'args' after select, got {opcode!r} {args!r}"
            )
        # args[0] is the protocol version the plugin speaks
        self.server_version = args[0] or PROTOCOL_VERSION
        wanted = args[1:]
        values = [params.get(name, "") for name in wanted]
        self._send(encode_instruction("connect", self.server_version, *values))

        opcode, args = self.read_instruction()
        if opcode == "error":
            raise GuacdConnectionError(
                args[0] if args else "guacd connection failed",
                int(args[1]) if len(args) > 1 and args[1].isdigit() else 0,
            )
        if opcode != "ready" or not args:
            raise GuacdProtocolError(
                f"Expected 'ready' after connect, got {opcode!r} {args!r}"
            )
        self.connection_id = args[0]
        return self.connection_id

    # -- client opcodes ------------------------------------------------
    def send_sync(self, timestamp_ms: int, frames: int = 0) -> None:
        """Keep-alive + output pacing; guacd flushes its queue on sync."""
        self._send(encode_instruction("sync", str(timestamp_ms), str(frames)))

    def send_ack(self, stream_id: str, error: str = "", status: int = 0) -> None:
        """Acknowledge a received stream blob (the flow-control half)."""
        self._send(
            encode_instruction("ack", str(stream_id), error, str(status))
        )

    def send_disconnect(self) -> None:
        try:
            self._send(encode_instruction("disconnect"))
        except (GuacdProtocolError, OSError):
            pass  # the socket may already be gone; closing still matters

    def send_mouse(
        self, x: int, y: int, button_mask: int, timestamp_ms: int
    ) -> None:
        self._send(
            encode_instruction("mouse", str(x), str(y), str(button_mask), str(timestamp_ms))
        )

    def send_key(self, keysym: int, pressed: bool, timestamp_ms: int) -> None:
        self._send(
            encode_instruction("key", str(keysym), "1" if pressed else "0", str(timestamp_ms))
        )
