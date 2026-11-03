"""Read the wizard's version-one forwarder ledger without extracting a tar."""

from __future__ import annotations

import base64
from collections.abc import Iterator
import binascii
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import termios
import zlib

from endpoint_validation import validate_https_endpoint


PREFIX = b"SIEM-FORWARDER-V1:"
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MEMBER_NAMES = {"logstash.yml", "pipeline.conf", "central-ca.crt", "README.md"}
TAR_BLOCK = tarfile.BLOCKSIZE
ZERO_BLOCK = bytes(TAR_BLOCK)
PAX_MTIME = re.compile(rb"([1-9][0-9]{0,4}) mtime=-?[0-9]+(?:\.[0-9]+)?\n")
LOGSTASH_TOKEN = re.compile(r"""\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|=>|[a-zA-Z0-9_-]+|.""", re.DOTALL)
LISTENER_PROTOCOLS = {
    "syslog": ("tcp", "udp"),
    "tcp": ("tcp",),
    "udp": ("udp",),
    "http": ("tcp",),
}


class HandoffError(ValueError):
    """A ledger cannot be read or installed safely."""


def read_ledger(path: Path | None) -> bytes:
    if path is not None:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise HandoffError("The handoff file must be a regular file.")
            return stream.read(MAX_LEDGER_BYTES + 1)

    stream = sys.stdin.buffer
    if not sys.stdin.isatty():
        return stream.read(MAX_LEDGER_BYTES + 1)

    fd = stream.fileno()
    original = termios.tcgetattr(fd)
    paste_mode = termios.tcgetattr(fd)
    # Canonical terminal input can silently discard bytes on long pasted lines.
    paste_mode[3] &= ~(termios.ICANON | termios.ECHO)
    paste_mode[6][termios.VMIN] = 1
    paste_mode[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, paste_mode)
    try:
        print("Paste the complete SIEM-FORWARDER-V1 ledger and press Enter.", file=sys.stderr, flush=True)
        return stream.readline(MAX_LEDGER_BYTES + 1)
    finally:
        termios.tcsetattr(fd, termios.TCSAFLUSH, original)
        print(file=sys.stderr)


def decompress(ledger: bytes) -> bytes:
    if len(ledger) > MAX_LEDGER_BYTES:
        raise HandoffError("The handoff exceeds the 4 MiB ledger limit.")
    ledger = ledger.strip()
    if not ledger.startswith(PREFIX):
        raise HandoffError("Expected the SIEM-FORWARDER-V1 prefix.")
    encoded = ledger[len(PREFIX):]
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except binascii.Error:
        raise HandoffError("The ledger payload must be standard padded Base64.") from None
    if not encoded or base64.b64encode(compressed) != encoded:
        raise HandoffError("The ledger payload must be standard padded Base64.")

    inflater = zlib.decompressobj(wbits=zlib.MAX_WBITS + 16)
    try:
        archive = inflater.decompress(compressed, MAX_ARCHIVE_BYTES + 1)
    except zlib.error:
        raise HandoffError("The ledger contains an invalid gzip stream.") from None
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise HandoffError("The handoff exceeds the 8 MiB decompressed limit.")
    if not inflater.eof or inflater.unused_data:
        raise HandoffError("Expected one complete gzip stream.")
    return archive


def read_archive(archive: bytes) -> dict[str, bytes]:
    members = {}
    offset = 0
    pending_mtime = False
    if len(archive) % TAR_BLOCK:
        raise HandoffError("The tar archive has an incomplete block.")

    while offset < len(archive):
        header = archive[offset:offset + TAR_BLOCK]
        if header == ZERO_BLOCK:
            if (
                pending_mtime
                or members.keys() != MEMBER_NAMES
                or len(archive) - offset < 2 * TAR_BLOCK
                or any(archive[offset:])
            ):
                raise HandoffError("The tar archive has missing members or an invalid ending.")
            return members

        try:
            member = tarfile.TarInfo.frombuf(header, "ascii", "surrogateescape")
        except (tarfile.HeaderError, ValueError, OverflowError):
            raise HandoffError("The tar archive contains an invalid header.") from None
        start = offset + TAR_BLOCK
        end = start + member.size
        offset = (end + TAR_BLOCK - 1) // TAR_BLOCK * TAR_BLOCK
        if member.size < 0 or offset > len(archive) or any(archive[end:offset]):
            raise HandoffError("The tar archive contains an invalid member size or padding.")

        content = archive[start:end]
        if member.type == tarfile.XHDTYPE:
            # Python's wizard writes a local PAX header for fractional mtime.
            # Path, link, size and all other overrides are disallowed.
            mtime = PAX_MTIME.fullmatch(content)
            if (
                pending_mtime or member.name != "././@PaxHeader" or member.linkname
                or mtime is None or int(mtime[1]) != len(content)
            ):
                raise HandoffError("The tar archive contains unsupported extended metadata.")
            pending_mtime = True
            continue

        if (
            member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
            or member.linkname or member.name not in MEMBER_NAMES or member.name in members
        ):
            raise HandoffError("The tar archive contains an unexpected or duplicate member.")
        members[member.name] = content
        pending_mtime = False

    raise HandoffError("The tar archive is missing its end marker.")


def read_handoff(path: Path | None) -> dict[str, bytes]:
    try:
        return read_archive(decompress(read_ledger(path)))
    except OSError:
        raise HandoffError("Could not read the handoff input.") from None


def pipeline_tokens(pipeline: bytes) -> list[str]:
    try:
        source = pipeline.decode("utf-8")
    except UnicodeError:
        raise HandoffError("The pipeline must use UTF-8.") from None

    return [
        token for token in LOGSTASH_TOKEN.findall(source)
        if not token.isspace() and not token.startswith("#")
    ]


def token_name(token: str) -> str:
    if len(token) >= 2 and token[0] in {"'", '"'} and token[-1] == token[0]:
        return token[1:-1]
    return token


def walk_pipeline(tokens: list[str]) -> Iterator[tuple[int, str, list[str]]]:
    """Yield each token with its enclosing configuration blocks."""
    blocks: list[str] = []
    for index, token in enumerate(tokens):
        yield index, token, blocks
        if token in {"{", "["}:
            if token == "[":
                name = "["
            else:
                previous = index - (2 if index and tokens[index - 1] == "=>" else 1)
                name = token_name(tokens[previous]) if previous >= 0 else ""
            blocks.append(name)
        elif token in {"}", "]"}:
            if not blocks or (blocks[-1] == "[") != (token == "]"):
                raise HandoffError("The pipeline contains unmatched braces or brackets.")
            blocks.pop()
    if blocks:
        raise HandoffError("The pipeline contains an incomplete block.")


def scalar_value(tokens: list[str], index: int) -> str:
    following = tokens[index + 2:index + 5]
    if len(following) >= 2 and (
        following[1] == "}" or len(following) == 3 and following[2] == "=>"
    ):
        return following[0]
    raise HandoffError("A wizard pipeline setting must use a single literal value.")


def parse_listeners(pipeline: bytes) -> list[tuple[int, str]]:
    tokens = pipeline_tokens(pipeline)
    listeners = []
    listener_port = None
    for index, token, blocks in walk_pipeline(tokens):
        if not blocks or blocks[0] != "input":
            continue
        if token == "{" and len(blocks) == 1:
            listener_port = None
        elif token == "}" and len(blocks) == 2:
            plugin = blocks[1]
            if plugin not in LISTENER_PROTOCOLS or listener_port is None:
                raise HandoffError("Every input must be a supported listener with a literal port.")
            listeners.append((listener_port, plugin))
        elif (
            len(blocks) == 2 and token_name(token) == "port"
            and tokens[index + 1:index + 2] == ["=>"]
        ):
            value = scalar_value(tokens, index)
            if listener_port is not None or not re.fullmatch(r"[0-9]{1,5}", value):
                raise HandoffError("Listener ports must be single decimal literals.")
            listener_port = int(value)
            if not 1 <= listener_port <= 65535:
                raise HandoffError("Listener ports must be between 1 and 65535.")
    if not listeners:
        raise HandoffError("The pipeline must contain a complete listener block.")
    return listeners


def listener_ports(pipeline: bytes) -> list[tuple[int, str]]:
    """Return published port/protocol pairs for the pipeline's listeners."""
    ports = [
        (port, protocol)
        for port, plugin in parse_listeners(pipeline)
        for protocol in LISTENER_PROTOCOLS[plugin]
    ]
    if len(ports) != len(set(ports)):
        raise HandoffError("Two listeners publish the same port and protocol.")
    return sorted(ports)


def syslog_ports(pipeline: bytes) -> list[int]:
    """Return the actual syslog listener ports for the operator's smoke event."""
    return sorted(port for port, plugin in parse_listeners(pipeline) if plugin == "syslog")


def string_value(token: str) -> str:
    if (
        len(token) >= 2 and token[0] in {"'", '"'} and token[-1] == token[0]
        and "\\" not in token and not any(ord(char) < 32 or ord(char) == 127 for char in token)
    ):
        return token[1:-1]
    raise HandoffError("Wizard identity fields must be quoted literals.")


def pipeline_identity(pipeline: bytes) -> tuple[str, str, str]:
    """Read the unambiguous queue owner and central HTTP destination."""
    tokens = pipeline_tokens(pipeline)
    slugs = []
    output = {}
    http_outputs = 0
    listener_slug = None
    has_add_field = False
    for index, token, blocks in walk_pipeline(tokens):
        if not blocks:
            if token == "{" and (not index or tokens[index - 1] not in {"input", "output"}):
                raise HandoffError("Expected a wizard pipeline with input and output sections.")
            continue

        section = blocks[0]
        name = token_name(token)
        assignment = tokens[index + 1:index + 2] == ["=>"]
        if section == "input":
            if token == "{" and len(blocks) == 1:
                listener_slug = None
                has_add_field = False
            elif token == "}" and len(blocks) == 2:
                if listener_slug is None:
                    raise HandoffError("Every wizard listener must set the customer slug.")
                slugs.append(listener_slug)
            elif len(blocks) == 2 and name == "add_field" and assignment:
                if has_add_field:
                    raise HandoffError("A wizard listener sets add_field more than once.")
                has_add_field = True
            elif len(blocks) == 3 and blocks[2] == "add_field" and assignment:
                if name in {"customer", "[customer]"} or "%{" in name:
                    raise HandoffError("Wizard listener metadata must identify one customer unambiguously.")
                if name == "[customer][slug]":
                    if listener_slug is not None:
                        raise HandoffError("A wizard listener sets the customer slug more than once.")
                    listener_slug = string_value(scalar_value(tokens, index))
        elif section == "output":
            if token == "{" and len(blocks) == 1:
                if token_name(tokens[index - 1]) != "http" or http_outputs:
                    raise HandoffError("Expected one direct HTTP output in the wizard pipeline.")
                http_outputs += 1
            elif len(blocks) == 2 and name in {"user", "url", "password"} and assignment:
                if name in output:
                    raise HandoffError("An HTTP output identity setting appears more than once.")
                output[name] = string_value(scalar_value(tokens, index))

    if not slugs or len(set(slugs)) != 1 or not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", slugs[0]):
        raise HandoffError("The wizard listeners must identify one valid customer slug.")
    username = output.get("user", "")
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,40}", username):
        raise HandoffError("The wizard pipeline must identify one valid HTTP output user.")
    if output.get("password") != "${CUSTOMER_FORWARDER_PASSWORD}":
        raise HandoffError("The HTTP output must read CUSTOMER_FORWARDER_PASSWORD at runtime.")
    endpoint = output.get("url", "")
    try:
        if "${" in endpoint:
            raise ValueError
        validate_https_endpoint(endpoint)
    except ValueError:
        raise HandoffError("The HTTP output must use a literal HTTPS endpoint.") from None
    return slugs[0], username, endpoint
