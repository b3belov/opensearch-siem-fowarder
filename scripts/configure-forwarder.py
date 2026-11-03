#!/usr/bin/env python3
"""Install an operator-issued onboarding ledger for the Compose forwarder."""
from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
import fcntl
import io
import json
import os
import re
import shlex
import shutil
import ssl
import stat
import subprocess
import tempfile
from pathlib import Path

import yaml

from forwarder_handoff import HandoffError, listener_ports, pipeline_identity, read_handoff, syslog_ports

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "data/forwarder-handoff"
ACTIVE = STATE / "compose.yml"
DISCONNECTING = STATE / "disconnecting"
SERVICE = "customer-forwarder"
LOGSTASH = "/usr/share/logstash"
DATA = f"{LOGSTASH}/data"
PASSWORD = "CUSTOMER_FORWARDER_PASSWORD"
SECRET_BINDING = "${CUSTOMER_FORWARDER_PASSWORD:?Set CUSTOMER_FORWARDER_PASSWORD in .env}"
DOTENV_ENTRY = re.compile(
    rb"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.\[\]-]*)[ \t]*(?:[=:][ \t]*|(?=[#\r\n]|$))"
)
QUEUE = ROOT / "data/logstash"
MANAGED = ("config/logstash.yml", "pipeline/pipeline.conf", "config/certs/central-ca.crt")
LOGSTASH_ARGS = ["--path.settings", f"{LOGSTASH}/config", "-f", f"{LOGSTASH}/pipeline/pipeline.conf"]
WIZARD_CA = re.compile(
    rb'(?m)^(?P<verify>[ \t]*ssl_verification_mode => "full"\r?\n)'
    rb'(?P<indent>[ \t]*)ssl_certificate_authorities[ \t]*=>[ \t]*'
    rb'\[[ \t]*(?P<ca>"/usr/share/logstash/config/certs/central-ca\.crt")[ \t]*\][ \t]*(?=\r?$)'
)


def require_secret() -> None:
    env_file = ROOT / ".env"
    if not env_file.exists():
        raise HandoffError("Set CUSTOMER_FORWARDER_PASSWORD in the repository's protected .env file.")
    mode = env_file.lstat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o077:
        raise HandoffError("The repository's .env must be a regular file with mode 0600 or stricter.")
    for line in reversed(env_file.read_text(encoding="utf-8").splitlines()):
        key, separator, value = line.strip().partition("=")
        if key.strip().removeprefix("export ") == PASSWORD:
            if separator and value.strip() not in {"", "''", '""', "<credential-password>"}:
                return
            break
    raise HandoffError("Set CUSTOMER_FORWARDER_PASSWORD in the repository's protected .env file.")


def check_settings(contents: bytes) -> None:
    settings = yaml.safe_load(contents)
    if not isinstance(settings, dict):
        raise HandoffError("logstash.yml must contain a mapping.")

    def setting(name, default):
        parent, key = name.split(".", 1)
        nested = settings.get(parent)
        return settings.get(name, nested.get(key, default) if isinstance(nested, dict) else default)

    if (setting("queue.type", None) != "persisted"
            or setting("path.data", DATA) != DATA
            or setting("path.queue", f"{DATA}/queue") != f"{DATA}/queue"):
        raise HandoffError("The ledger must use a persisted queue under the mounted Logstash data directory.")
    if setting("config.debug", False) is not False or setting("log.level", "info") in ("trace", "debug"):
        raise HandoffError("Disable Logstash configuration debug logging in the operator-issued ledger.")


def compose_command(path: Path) -> list[str]:
    return [
        "env", "-u", PASSWORD, "docker", "compose",
        "--project-directory", str(ROOT), "--env-file", str(ROOT / ".env"), "-f", str(path),
    ]


def bind(source: Path, target: str, *, read_only: bool) -> dict:
    return {
        "type": "bind", "source": str(source), "target": f"{LOGSTASH}/{target}",
        "read_only": read_only, "bind": {"create_host_path": False},
    }


def published(listeners: list[tuple[int, str]]) -> list[str]:
    if (9600, "tcp") in listeners:
        raise HandoffError("A listener conflicts with the forwarder's monitoring port 9600/tcp.")
    return [f"{port}:{port}/{protocol}" for port, protocol in listeners]


def initial_deployment() -> dict:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_bytes())
    service = compose["services"][SERVICE]
    del service["env_file"]
    service["environment"] = {
        "LS_JAVA_OPTS": service["environment"]["LS_JAVA_OPTS"],
        PASSWORD: SECRET_BINDING,
    }
    service["volumes"] = [bind(QUEUE, "data", read_only=False)]
    service["ports"] = ["127.0.0.1:9600:9600/tcp"]
    service["entrypoint"] = [f"{LOGSTASH}/bin/logstash"]
    service["command"] = LOGSTASH_ARGS
    return compose


def managed_mounts(service: dict) -> dict:
    mounts = {}
    for mount in service["volumes"]:
        if not isinstance(mount, dict):
            # Unrelated short-form mounts may coexist with the managed binds.
            if isinstance(mount, str) and not any(
                f":{LOGSTASH}/{name}" in mount for name in (*MANAGED, "data")
            ):
                continue
            raise HandoffError("The active deployment has an ambiguous Logstash mount.")
        target = mount.get("target")
        if target not in {f"{LOGSTASH}/{name}" for name in (*MANAGED, "data")}:
            continue
        if target in mounts or mount.get("type") != "bind":
            raise HandoffError("The active deployment has an ambiguous Logstash mount.")
        mounts[target] = mount
    return mounts


def active_deployment() -> tuple[dict, dict[str, bytes], Path, bytes]:
    try:
        if ACTIVE.is_symlink() or not ACTIVE.is_file():
            raise ValueError
        manifest = ACTIVE.read_bytes()
        compose = yaml.safe_load(manifest)
        service = compose["services"][SERVICE]
        if service["command"] != LOGSTASH_ARGS or service["entrypoint"] != [f"{LOGSTASH}/bin/logstash"]:
            raise ValueError
        if service["environment"].get(PASSWORD) != SECRET_BINDING:
            raise HandoffError("The active password binding is missing or ambiguous. Restore its original .env binding before updating.")
        mounts = managed_mounts(service)
        paths = {name: Path(mounts[f"{LOGSTASH}/{name}"]["source"]) for name in MANAGED}
        pipeline = paths["pipeline/pipeline.conf"]
        revision = pipeline.parent.parent
        if revision.parent != STATE or not revision.name.startswith("revision-"):
            raise ValueError
        for name, path in paths.items():
            if (path != revision / name or path.resolve() != path or not path.is_file()
                    or mounts[f"{LOGSTASH}/{name}"].get("read_only") is not True):
                raise ValueError
        queue = Path(mounts[DATA]["source"])
        if (queue.resolve() != queue or not queue.is_dir() or mounts[DATA].get("read_only")
                or not (queue == QUEUE or (
                    queue.name == "logstash-data" and queue.parent.parent == STATE
                    and queue.parent.name.startswith("revision-")
                ))):
            raise ValueError
        return compose, {name: path.read_bytes() for name, path in paths.items()}, queue, manifest
    except (OSError, AttributeError, KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        if isinstance(exc, HandoffError):
            raise
        raise HandoffError("The active forwarder configuration is incomplete or ambiguous. Restore its Compose file and managed files before retrying.") from None


def check_initial_state() -> None:
    manual_keys = {"CENTRAL_INGEST_URL", "CUSTOMER_FORWARDER_USERNAME"}
    env_file = ROOT / ".env"
    manual_binding = any(os.environ.get(key) for key in manual_keys)
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, _, value = line.strip().removeprefix("export ").partition("=")
            if key.strip() in manual_keys and value.strip() not in {"", "''", '""'}:
                manual_binding = True
    if (manual_binding or (ROOT / "certs/central-ca.crt").exists()
            or QUEUE.is_symlink() or (QUEUE.exists() and (not QUEUE.is_dir() or any(QUEUE.iterdir())))):
        raise HandoffError("A manual or incomplete forwarder configuration already exists. Its customer identity cannot be verified for a ledger update.")
    if any(STATE.glob("revision-*")):
        raise HandoffError("Ledger revisions exist without an active Compose file. Restore the active file before retrying.")


def check_container(update: bool) -> None:
    if not shutil.which("docker"):
        return
    result = docker([
        "docker", "container", "inspect", "--format",
        '{{ index .Config.Labels "com.docker.compose.project.config_files" }}', SERVICE,
    ], capture=True, timeout=15)
    if result.returncode == 0 and (not update or result.stdout.strip() != os.fsencode(ACTIVE)):
        raise HandoffError("The existing forwarder container uses a different Compose configuration. Verify its deployment before retrying.")


def updated_ports(ports: list, old_ports: list[str], new_ports: list[str]) -> list:
    if not isinstance(ports, list) or any(ports.count(port) != 1 for port in old_ports):
        raise HandoffError("The active deployment's listener bindings are incomplete or ambiguous.")
    retained = [port for port in ports if port not in old_ports]
    # Preserve unrelated publications, including the monitoring endpoint.
    for binding in retained:
        if isinstance(binding, dict):
            host, protocol = str(binding.get("published", "")), binding.get("protocol", "tcp")
        elif isinstance(binding, str):
            address, _, protocol = binding.partition("/")
            host = address.rsplit(":", 2)[-2] if ":" in address else ""
            protocol = protocol or "tcp"
        else:
            continue
        bounds = host.split("-", 1)
        if host and all(bound.isdecimal() for bound in bounds):
            first, last = int(bounds[0]), int(bounds[-1])
            for port in new_ports:
                if port.endswith(f"/{protocol}") and first <= int(port.split(":", 1)[0]) <= last:
                    raise HandoffError("The new listener conflicts with an existing local port binding.")
    return retained + new_ports


def set_revision(compose: dict, revision: Path, ports: list) -> None:
    service = compose["services"][SERVICE]
    service["ports"] = ports
    managed = managed_mounts(service)
    for name in MANAGED:
        target = f"{LOGSTASH}/{name}"
        if target in managed:
            managed[target]["source"] = str(revision / name)
        else:
            service["volumes"].append(bind(revision / name, name, read_only=True))


def docker(args: list[str], *, capture: bool = False, timeout: int = 300):
    return subprocess.run(
        args, cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=timeout,
    )


def validate(compose: dict, queue: Path, *, initialize_queue: bool = False) -> bool:
    if not shutil.which("docker") or docker(["docker", "compose", "version"], timeout=15).returncode:
        return False

    with tempfile.TemporaryDirectory(dir=STATE) as scratch:
        path = Path(scratch) / "compose.yml"
        checks = copy.deepcopy(compose)
        service = checks["services"][SERVICE]
        service["logging"] = {"driver": "none"}
        service["network_mode"] = "none"
        service.pop("networks", None)
        del service["ports"]
        path.write_text(yaml.safe_dump(checks), encoding="utf-8")
        command = compose_command(path)
        resolved = docker(command + ["config", "--format", "json"], capture=True)
        if resolved.returncode:
            raise HandoffError("Compose could not resolve the deployment and .env file.")
        password = json.loads(resolved.stdout)["services"][SERVICE]["environment"].get(PASSWORD)
        if not password or password == "<credential-password>":
            raise HandoffError("Compose did not resolve a password from .env.")

        if docker(["docker", "info"], timeout=20).returncode:
            return False

        run = command + ["run", "--rm", "--no-deps", "-T"]
        probe = [
            "--entrypoint", "/bin/sh", SERVICE, "-ec",
            f'id -u; id -g; test -w {DATA} && '
            f'{{ test ! -e {DATA}/queue || test -w {DATA}/queue; }} && '
            f'{{ test ! -e {DATA}/queue/main || test -w {DATA}/queue/main; }}',
        ]
        result = docker(run + probe, capture=True)
        if result.returncode:
            ids = result.stdout.split()
            if len(ids) == 2 and all(value.isdigit() for value in ids) and initialize_queue and not any(queue.iterdir()):
                owner = b":".join(ids).decode("ascii")
                docker(run + ["--user", "0", "--entrypoint", "/bin/chown", SERVICE, owner, DATA])
                result = docker(run + probe)
            if result.returncode:
                raise HandoffError(
                    f"The pinned image could not start or its queue mount at {queue} is not writable. "
                    "Check the directory permissions for the Logstash container user."
                )

        # Use the same settings and paths without locking or changing a real queue.
        service["volumes"].remove(managed_mounts(service)[DATA])
        service["tmpfs"] = [f"{DATA}:mode=1777"]
        path.write_text(yaml.safe_dump(checks), encoding="utf-8")
        if docker(run + [SERVICE, *service["command"], "--config.test_and_exit"]).returncode:
            raise HandoffError("The pinned Logstash runtime rejected the ledger. Ask the SIEM operator for a compatible handoff.")
        return True


def stage_files(revision: Path, files: dict[str, bytes], effective: bytes) -> None:
    for name in ("config/certs", "pipeline"):
        (revision / name).mkdir(parents=True)
    # Bind-mounted files must be readable by the image's unprivileged user.
    # The revision and its parent still restrict access on the host.
    for name in ("config", "config/certs", "pipeline"):
        (revision / name).chmod(0o755)
    for name, target in (
        ("logstash.yml", "config/logstash.yml"),
        ("central-ca.crt", "config/certs/central-ca.crt"),
        ("pipeline.conf", "pipeline.conf"),
        ("README.md", "README.md"),
    ):
        (revision / target).write_bytes(files[name])
    # The pinned HTTP output uses the legacy spelling for the same CA.
    # Retain the issued pipeline and leave its full TLS verification intact.
    pipeline = revision / "pipeline/pipeline.conf"
    pipeline.write_bytes(effective)
    for path in (pipeline, revision / "config/logstash.yml", revision / "config/certs/central-ca.crt"):
        path.chmod(0o644)


def confirm_action(confirmed: bool, action: str) -> None:
    if confirmed:
        return
    try:
        with open("/dev/tty", "r", encoding="utf-8") as terminal:
            print(f"{action}? [y/N] ", end="", flush=True)
            if terminal.readline().strip().lower() in {"y", "yes"}:
                return
    except OSError:
        raise HandoffError("Review the action above and rerun with --yes to confirm.") from None
    raise HandoffError("Action declined. The active configuration was kept.")


@contextmanager
def state_lock():
    if STATE.parent.is_symlink():
        raise HandoffError("The repository data directory must not be a symlink.")
    mode = STATE.lstat().st_mode
    if not stat.S_ISDIR(mode) or mode & 0o077:
        raise HandoffError("The ledger state directory must be private and must not be a symlink.")
    fd = os.open(STATE, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def ledger_container() -> str | None:
    if not shutil.which("docker"):
        raise HandoffError("Docker is required to confirm that the ledger container is stopped.")
    found = docker([
        "docker", "container", "ls", "--all", "--filter", f"name=^/{SERVICE}$",
        "--format", "{{.ID}}",
    ], capture=True, timeout=20)
    if found.returncode:
        raise HandoffError("Cannot check the Docker daemon. Restore Docker access and retry disconnect.")
    if not found.stdout.strip():
        return None
    container = found.stdout.strip().decode("ascii")
    if not re.fullmatch(r"[0-9a-f]{12,64}", container):
        raise HandoffError("Docker returned an ambiguous forwarder container identity.")
    label = docker([
        "docker", "container", "inspect", "--format",
        '{{ index .Config.Labels "com.docker.compose.project.config_files" }}', container,
    ], capture=True, timeout=20)
    if label.returncode or label.stdout.strip() != os.fsencode(ACTIVE):
        raise HandoffError("The existing forwarder container is not owned by this ledger deployment.")
    return container


def disconnect_container(container: str) -> None:
    if docker(["docker", "container", "stop", "--timeout", "60", container], timeout=90).returncode:
        raise HandoffError("Docker could not stop the ledger forwarder. Retry disconnect after checking Docker.")
    if docker(["docker", "container", "rm", container], timeout=30).returncode:
        raise HandoffError("Docker could not remove the stopped ledger forwarder. Retry disconnect after checking Docker.")


def without_forwarder_password(contents: bytes) -> bytes:
    bom = b"\xef\xbb\xbf" if contents.startswith(b"\xef\xbb\xbf") else b""
    kept = [bom]
    quoted = None
    removing = False
    for line in io.BytesIO(contents[len(bom):]):
        value = line
        if quoted is None:
            entry = DOTENV_ENTRY.match(line)
            if entry is None and line.strip() and not line.lstrip().startswith(b"#"):
                raise HandoffError("The shared .env has an unrecognized entry. Fix it before disconnecting.")
            removing = bool(entry and entry[1] == PASSWORD.encode("ascii"))
            if entry:
                value = line[entry.end():]
                if value[:1] in (b"'", b'"'):
                    quoted = value[:1]
                    value = value[1:]
        if not removing:
            kept.append(line)
        if quoted:
            for token in re.finditer(rb"\\.|" + re.escape(quoted), value):
                if token[0] == quoted:
                    trailing = value[token.end():].strip()
                    if trailing and not trailing.startswith(b"#"):
                        raise HandoffError("The shared .env has content after a quoted value. Put each entry on its own line before disconnecting.")
                    quoted = None
                    break
    if quoted is not None:
        raise HandoffError("The shared .env has an unterminated quoted value. Fix it before disconnecting.")
    return b"".join(kept)


def read_disconnect_env() -> tuple[bytes, os.stat_result] | None:
    path = ROOT / ".env"
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise HandoffError("The shared .env must be a regular file before disconnecting.")
            return stream.read(), info
    except FileNotFoundError:
        return None


def remove_forwarder_password(original: tuple[bytes, os.stat_result] | None, remaining: bytes) -> None:
    if original is None or original[0] == remaining:
        return
    info = original[1]
    fd, name = tempfile.mkstemp(prefix=".env.disconnect-", dir=ROOT)
    candidate = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            if (info.st_uid, info.st_gid) != (os.geteuid(), os.fstat(stream.fileno()).st_gid):
                os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            stream.write(remaining)
        current = read_disconnect_env()
        if current is None or current[0] != original[0] or any(
            getattr(current[1], field) != getattr(info, field)
            for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_mtime_ns")
        ):
            raise HandoffError("The shared .env changed during disconnect. Review it and retry.")
        os.replace(candidate, ROOT / ".env")
    finally:
        candidate.unlink(missing_ok=True)


def disconnect(confirmed: bool) -> None:
    if not STATE.exists() and not STATE.is_symlink():
        print("No ledger configuration is installed.")
        return
    with state_lock():
        if DISCONNECTING.is_symlink() or (DISCONNECTING.exists() and not DISCONNECTING.is_file()):
            raise HandoffError("An unexpected disconnect marker prevents safe cleanup.")
        paths = [ACTIVE]
        directories = []
        for revision in sorted(STATE.glob("revision-*")):
            if not revision.is_dir() or revision.is_symlink():
                raise HandoffError("An unexpected ledger revision path prevents safe disconnect.")
            paths.extend(revision / name for name in (
                *MANAGED, "pipeline.conf", "README.md", "compose.yml",
                "previous-compose.yml", "activate.yml",
            ))
            directories.extend(revision / name for name in ("config/certs", "config", "pipeline", "."))
        paths = [path for path in paths if path.exists() or path.is_symlink()]
        if not paths and not DISCONNECTING.exists():
            print("No ledger configuration is installed.")
            return
        if any(path.parent.resolve() != path.parent or path.is_dir() for path in paths):
            raise HandoffError("An unexpected configuration path prevents safe disconnect.")
        env = read_disconnect_env()
        remaining_env = without_forwarder_password(env[0]) if env else b""
        print("Disconnect will stop and remove the ledger container and delete its configuration and rollback copies.")
        print("The forwarder password entry will be removed from the shared .env.")
        print("Persistent queue data and unrelated local files will be retained.", flush=True)
        confirm_action(confirmed, "Disconnect the ledger forwarder")
        container = ledger_container()
        DISCONNECTING.touch()
        if container is not None:
            disconnect_container(container)
        remove_forwarder_password(env, remaining_env)
        for path in paths:
            path.unlink(missing_ok=True)
        for directory in directories:
            if directory.resolve() == directory and directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()
        DISCONNECTING.unlink()
    print("Ledger configuration deleted. Persistent queue data was retained.")


def report_changes(old: dict, new: dict, old_endpoint: str, endpoint: str,
                   old_ports: list[str], ports: list[str]) -> None:
    print("Regenerated ledger changes")
    if old_endpoint != endpoint:
        print(f"  Central HTTPS endpoint: {old_endpoint} -> {endpoint}")
    if old_ports != ports:
        print(f"  Published listeners: {', '.join(old_ports)} -> {', '.join(ports)}")
    for name, label in zip(MANAGED, ("Logstash settings", "Logstash pipeline", "Public CA")):
        if old[name] != new[name]:
            print(f"  {label} changed")
    print(flush=True)


def install(files: dict[str, bytes], confirmed: bool) -> None:
    slug, username, endpoint = pipeline_identity(files["pipeline.conf"])
    check_settings(files["logstash.yml"])
    listeners = listener_ports(files["pipeline.conf"])
    ports = published(listeners)
    effective = WIZARD_CA.sub(rb'\g<verify>\g<indent>cacert => \g<ca>', files["pipeline.conf"])
    new = dict(zip(MANAGED, (files["logstash.yml"], effective, files["central-ca.crt"])))

    if STATE.parent.is_symlink():
        raise HandoffError("The repository data directory must not be a symlink.")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with state_lock():
        if DISCONNECTING.exists():
            raise HandoffError("A disconnect is incomplete. Rerun with --disconnect before installing.")
        update = ACTIVE.exists() or ACTIVE.is_symlink()
        smoke_ports = syslog_ports(effective)
        if update:
            compose, old, queue, original_manifest = active_deployment()
            try:
                old_slug, old_username, old_endpoint = pipeline_identity(old["pipeline/pipeline.conf"])
                check_settings(old["config/logstash.yml"])
                old_ports = published(listener_ports(old["pipeline/pipeline.conf"]))
            except HandoffError as exc:
                raise HandoffError(f"Cannot reliably identify the active customer or queue. {exc}") from None
            mismatch = []
            if old_slug != slug:
                mismatch.append("customer slug")
            if old_username != username:
                mismatch.append("credential username")
            if mismatch:
                raise HandoffError(
                    f"Incoming identity differs from the active pipeline ({', '.join(mismatch)}). "
                    "Use a separate operator workflow to change customers or credentials."
                )
            check_container(update)
            require_secret()
            bindings = updated_ports(compose["services"][SERVICE].get("ports"), old_ports, ports)
            if old == new:
                verified = validate(compose, queue)
                print("The ledger configuration is already current.")
                print_instructions(listeners, smoke_ports, verified)
                return
            report_changes(old, new, old_endpoint, endpoint, old_ports, ports)
            confirm_action(confirmed, "Apply this ledger update")
        else:
            require_secret()
            check_initial_state()
            check_container(update)
            compose, queue = initial_deployment(), QUEUE
            bindings = updated_ports(compose["services"][SERVICE]["ports"], [], ports)

        revision = Path(tempfile.mkdtemp(prefix="revision-", dir=STATE))
        candidate = revision / "activate.yml"
        activating = False
        created_queue = False
        try:
            stage_files(revision, files, effective)
            try:
                ssl.create_default_context(cafile=str(revision / "config/certs/central-ca.crt"))
            except ssl.SSLError:
                raise HandoffError("central-ca.crt must be a parseable CA trust file.") from None

            set_revision(compose, revision, bindings)
            if not update and not queue.exists():
                queue.mkdir(mode=0o755)
                queue.chmod(0o755)
                created_queue = True
            verified = validate(compose, queue, initialize_queue=not update)
            manifest = revision / "compose.yml"
            manifest.write_text(yaml.safe_dump(compose), encoding="utf-8")
            if update:
                _, active_files, _, active_manifest = active_deployment()
                if active_manifest != original_manifest or active_files != old:
                    raise HandoffError("The active configuration changed during installation. Review it and retry.")
                (revision / "previous-compose.yml").write_bytes(original_manifest)
            candidate.write_bytes(manifest.read_bytes())
            activating = True
            os.replace(candidate, ACTIVE)
        except BaseException:
            # A signal may arrive just after the atomic rename.
            if not activating or candidate.exists():
                shutil.rmtree(revision)
                if created_queue and not any(queue.iterdir()):
                    queue.rmdir()
            raise
    print(f"Installed handoff documentation in {revision / 'README.md'}")
    if update:
        print(f"Saved previous configuration in {revision / 'previous-compose.yml'}")
    print_instructions(listeners, smoke_ports, verified)


def print_instructions(listeners: list[tuple[int, str]], syslog: list[int], verified: bool) -> None:
    if verified:
        print("Logstash configuration and persistent queue mount validated.")
    else:
        print("Docker Compose or the daemon is unavailable. Rerun on the deployment host before starting Logstash.")
    print("Start or reload explicitly with the following command.")
    print(shlex.join(compose_command(ACTIVE) + ["up", "-d", "--force-recreate", SERVICE]))
    print("Configure senders with the forwarder host's reachable address and these published ports.")
    for port, protocol in listeners:
        print(f"  {port}/{protocol}")
    if not syslog:
        return
    print("Send a tagged syslog event from an authorized Linux sender.")
    print("""read -r -p 'Forwarder host: ' forwarder_host""")
    print('probe_id="siem-handoff-$(date -u +%Y%m%dT%H%M%SZ)-$$"')
    for port in syslog:
        print(f'logger --rfc3164 --tcp --server "$forwarder_host" --port {port} --tag siem-handoff "$probe_id"')
    print(r'printf "%s\n" "$probe_id"')
    print("Share the probe ID with the SIEM operator.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--file", type=Path, help="Read the ledger from a saved handoff file")
    mode.add_argument("--disconnect", action="store_true", help="Remove the ledger deployment and its configuration")
    parser.add_argument("--yes", "--replace", action="store_true", help="Confirm an update or disconnect")
    args = parser.parse_args()
    try:
        if args.disconnect:
            disconnect(args.yes)
        else:
            install(read_handoff(args.file), args.yes)
    except HandoffError as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    except (OSError, ValueError, RecursionError, yaml.YAMLError, subprocess.SubprocessError):
        parser.exit(1, "ERROR: Could not complete the requested action. Check local files, permissions and Docker availability.\n")
    except KeyboardInterrupt:
        parser.exit(130, "\nInstallation interrupted.\n")


if __name__ == "__main__":
    main()
