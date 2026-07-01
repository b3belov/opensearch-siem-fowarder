#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTTP_USERNAME = "windows-forwarder"
HTTP_PASSWORD = "test-http-password"


def run(command: list[str]) -> None:
    subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def docker_available() -> bool:
    return shutil.which("docker") is not None and subprocess.run(
        ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    ).returncode == 0


def logstash_image() -> str:
    for line in (ROOT / "docker-compose.yml").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("image:"):
            return stripped.split(":", 1)[1].strip()
    raise RuntimeError("customer-forwarder docker-compose.yml does not define an image")


def create_http_cert_material(http_certs: Path) -> tuple[Path, Path, Path]:
    http_certs.mkdir(parents=True, exist_ok=True)
    ca_key = http_certs / "ca.key"
    ca_cert = http_certs / "client-ca.crt"
    server_key = http_certs / "server.key"
    server_pkcs8 = http_certs / "server.pkcs8.key"
    server_csr = http_certs / "server.csr"
    server_cert = http_certs / "server.crt"
    server_ext = http_certs / "server.ext"
    client_key = http_certs / "client.key"
    client_csr = http_certs / "client.csr"
    client_cert = http_certs / "client.crt"
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1",
        "-subj", "/CN=parser-smoke-ca", "-batch",
    ])
    run([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(server_key), "-out", str(server_csr),
        "-subj", "/CN=localhost", "-batch",
    ])
    server_ext.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
        encoding="utf-8",
    )
    run([
        "openssl", "x509", "-req", "-in", str(server_csr),
        "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(server_cert), "-days", "1", "-extfile", str(server_ext),
    ])
    run([
        "openssl", "pkcs8", "-topk8", "-nocrypt",
        "-in", str(server_key), "-out", str(server_pkcs8),
    ])
    run([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(client_key), "-out", str(client_csr),
        "-subj", "/CN=parser-smoke-client", "-batch",
    ])
    run([
        "openssl", "x509", "-req", "-in", str(client_csr),
        "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(client_cert), "-days", "1",
    ])
    return ca_cert, client_cert, client_key


def mapped_port(container: str, private_port: int) -> int:
    rendered = subprocess.check_output(["docker", "port", container, f"{private_port}/tcp"], text=True).strip()
    return int(rendered.rsplit(":", 1)[1])


def post_json(url: str, path: Path, context: ssl.SSLContext) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    auth = base64.b64encode(f"{HTTP_USERNAME}:{HTTP_PASSWORD}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        if response.status >= 300:
            raise RuntimeError(f"unexpected HTTP status {response.status}")


def send_syslog(host: str, port: int, message: str) -> None:
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(message.encode("utf-8") + b"\n")


def main() -> None:
    if not docker_available():
        print("docker unavailable; skipped customer forwarder parser smoke")
        return
    image = logstash_image()
    if "@sha256:" not in image or "<resolved-image-digest>" in image:
        raise RuntimeError("customer-forwarder image must be pinned by a resolved @sha256 digest")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        config = tmp_path / "config"
        pipeline = tmp_path / "pipeline"
        output = tmp_path / "out"
        data = tmp_path / "data"
        http_certs = tmp_path / "http-certs"
        shutil.copytree(ROOT / "config", config)
        shutil.copytree(ROOT / "pipeline", pipeline)
        ca_cert, client_cert, client_key = create_http_cert_material(http_certs)
        ssl_context = ssl.create_default_context(cafile=str(ca_cert))
        ssl_context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
        output.mkdir()
        data.mkdir()
        (pipeline / "90-output-ingest-edge.conf").write_text(
            """
input { pipeline { address => "output-ingest-edge" } }
output {
  file {
    path => "/tmp/customer-forwarder-parser/events.jsonl"
    codec => json_lines
  }
}
""".lstrip(),
            encoding="utf-8",
        )
        logstash_yml = config / "logstash.yml"
        logstash_yml.write_text(
            logstash_yml.read_text(encoding="utf-8")
            + "\npath.data: /tmp/customer-forwarder-data\n",
            encoding="utf-8",
        )

        container = subprocess.check_output(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "-p",
                "127.0.0.1::5514/tcp",
                "-p",
                "127.0.0.1::8081/tcp",
                "-p",
                "127.0.0.1::8082/tcp",
                "-e",
                f"WINDOWS_HTTP_USERNAME={HTTP_USERNAME}",
                "-e",
                f"WINDOWS_HTTP_PASSWORD={HTTP_PASSWORD}",
                "-v",
                f"{config}:/usr/share/logstash/config:ro",
                "-v",
                f"{pipeline}:/usr/share/logstash/pipeline:ro",
                "-v",
                f"{http_certs}:/usr/share/logstash/config/http:ro",
                "-v",
                f"{output}:/tmp/customer-forwarder-parser",
                "-v",
                f"{data}:/tmp/customer-forwarder-data",
                image,
                "logstash",
                "--path.settings",
                "/usr/share/logstash/config",
            ],
            text=True,
        ).strip()
        try:
            windows_ad_port = mapped_port(container, 8081)
            windows_sysmon_port = mapped_port(container, 8082)
            syslog_port = mapped_port(container, 5514)
            deadline = time.time() + 90
            while time.time() < deadline:
                try:
                    post_json(f"https://localhost:{windows_ad_port}/", ROOT / "test/fixtures/windows-ad.json", ssl_context)
                    break
                except Exception:
                    time.sleep(2)
            else:
                raise RuntimeError("logstash parser smoke did not become ready")

            forged = json.loads((ROOT / "test/fixtures/windows-ad.json").read_text(encoding="utf-8"))
            forged["siem"] = {"source_id": "windows-sysmon"}
            forged_path = tmp_path / "forged-windows-ad.json"
            forged_path.write_text(json.dumps(forged), encoding="utf-8")
            post_json(f"https://localhost:{windows_ad_port}/", forged_path, ssl_context)
            post_json(f"https://localhost:{windows_sysmon_port}/", ROOT / "test/fixtures/windows-sysmon.json", ssl_context)
            send_syslog("127.0.0.1", syslog_port, (ROOT / "test/fixtures/generic-syslog.log").read_text(encoding="utf-8"))

            events_file = output / "events.jsonl"
            deadline = time.time() + 60
            while time.time() < deadline:
                if events_file.exists() and len(events_file.read_text(encoding="utf-8").splitlines()) >= 4:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("logstash parser smoke did not write expected events")
            events = [json.loads(line) for line in events_file.read_text(encoding="utf-8").splitlines()]
            source_ids = [event["siem"]["source_id"] for event in events]
            assert source_ids.count("windows-ad") >= 2
            assert "windows-sysmon" in source_ids
            assert "generic-syslog" in source_ids
            assert any(
                event["siem"]["source_id"] == "windows-ad"
                and event["event"]["code"] == "4625"
                and event["event"]["action"] == "logon-failed"
                and event["event"]["outcome"] == "failure"
                for event in events
            )
            assert any(
                event["siem"]["source_id"] == "windows-sysmon"
                and event["event"]["code"] == "3"
                and event["event"]["action"] == "network-connection"
                and event["event"]["category"] == "network"
                for event in events
            )
            for event in events:
                assert event["observer"]["name"] == "customer-forwarder-01"
                assert event["event"]["dataset"] == event["siem"]["source_id"]
                assert event["event"]["original"]
                assert event["event"]["ingested"]
        finally:
            subprocess.run(["docker", "rm", "-f", container], check=False)

    print("customer forwarder parser smoke passed")


if __name__ == "__main__":
    main()
