from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-env.py"


def write_ca(tmp_path: Path) -> Path:
    ca_dir = tmp_path / "certs"
    ca_dir.mkdir(parents=True, exist_ok=True)
    key = ca_dir / "central-ca.key"
    cert = ca_dir / "central-ca.crt"
    key.unlink(missing_ok=True)
    cert.unlink(missing_ok=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=test-central-ca",
            "-batch",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    return cert


def run_validator(root: Path, env_file: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), "--env-file", str(env_file)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def write_valid_env(tmp_path: Path, **overrides: str) -> Path:
    write_ca(tmp_path)
    values = {
        "CENTRAL_INGEST_URL": "https://siem.example.com:5044/",
        "CUSTOMER_FORWARDER_USERNAME": "acme-primary",
        "CUSTOMER_FORWARDER_PASSWORD": "not-a-placeholder",
        "CENTRAL_CA_CERT": "/usr/share/logstash/config/certs/central-ca.crt",
        "LS_JAVA_OPTS": '"-Xms512m -Xmx512m"',
        "FORWARDER_MEM_LIMIT": "1g",
        "WINDOWS_HTTP_USERNAME": "windows-forwarder",
        "WINDOWS_HTTP_PASSWORD": "not-a-placeholder",
    }
    values.update(overrides)
    env_file = tmp_path / ".env"
    env_file.write_text("\n".join(f"{key}={value}" for key, value in values.items()) + "\n", encoding="utf-8")
    return env_file


def test_env_validation_accepts_safe_values(tmp_path: Path) -> None:
    result = run_validator(tmp_path, write_valid_env(tmp_path))
    assert result.returncode == 0, result.stdout
    assert "customer forwarder environment valid" in result.stdout


def test_env_validation_rejects_http(tmp_path: Path) -> None:
    result = run_validator(tmp_path, write_valid_env(tmp_path, CENTRAL_INGEST_URL="http://siem.example.com:5044/"))
    assert result.returncode != 0
    assert "must use https" in result.stdout


def test_env_validation_rejects_placeholder_password(tmp_path: Path) -> None:
    result = run_validator(tmp_path, write_valid_env(tmp_path, CUSTOMER_FORWARDER_PASSWORD="change-me"))
    assert result.returncode != 0
    assert "must be replaced" in result.stdout


def test_env_validation_rejects_command_substitution_without_executing(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    env_file = write_valid_env(tmp_path, CUSTOMER_FORWARDER_PASSWORD="$(touch {})".format(marker))
    result = run_validator(tmp_path, env_file)
    assert result.returncode != 0
    assert "command substitution is not allowed" in result.stdout
    assert not marker.exists()


def test_env_validation_rejects_ca_path_outside_mounted_cert_dir(tmp_path: Path) -> None:
    outside_ca = tmp_path / "outside-ca.crt"
    write_ca(tmp_path)
    outside_ca.write_text((tmp_path / "certs" / "central-ca.crt").read_text(encoding="utf-8"), encoding="utf-8")
    result = run_validator(tmp_path, write_valid_env(tmp_path, CENTRAL_CA_CERT=str(outside_ca)))
    assert result.returncode != 0
    assert "must be under /usr/share/logstash/config/certs/" in result.stdout


def test_env_validation_rejects_non_pem_ca(tmp_path: Path) -> None:
    env_file = write_valid_env(tmp_path)
    (tmp_path / "certs" / "central-ca.crt").write_text("test ca\n", encoding="utf-8")
    result = run_validator(tmp_path, env_file)
    assert result.returncode != 0
    assert "must be a parseable CA trust file" in result.stdout


def test_env_validation_rejects_fake_pem_wrapper(tmp_path: Path) -> None:
    env_file = write_valid_env(tmp_path)
    (tmp_path / "certs" / "central-ca.crt").write_text(
        "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    result = run_validator(tmp_path, env_file)
    assert result.returncode != 0
    assert "must be a parseable CA trust file" in result.stdout


def test_env_validation_rejects_invalid_central_credential_ids(tmp_path: Path) -> None:
    for username in ["Acme-primary", "acme_primary", "acme.primary", "acme:primary", "a" * 42]:
        result = run_validator(tmp_path, write_valid_env(tmp_path, CUSTOMER_FORWARDER_USERNAME=username))
        assert result.returncode != 0
        assert "must match central credential id pattern" in result.stdout


def test_env_validation_rejects_invalid_windows_http_credentials(tmp_path: Path) -> None:
    bad_user = run_validator(tmp_path, write_valid_env(tmp_path, WINDOWS_HTTP_USERNAME="bad user"))
    assert bad_user.returncode != 0
    assert "WINDOWS_HTTP_USERNAME contains unsupported characters" in bad_user.stdout

    placeholder_password = run_validator(tmp_path, write_valid_env(tmp_path, WINDOWS_HTTP_PASSWORD="change-me"))
    assert placeholder_password.returncode != 0
    assert "WINDOWS_HTTP_PASSWORD must be replaced" in placeholder_password.stdout
