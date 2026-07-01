#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_root="$(cd "$repo_root/.." && pwd)"
python_cmd="${PYTHON:-python3}"
if [[ "$python_cmd" != /* && -x "$project_root/$python_cmd" ]]; then
  python_cmd="$project_root/$python_cmd"
fi
cd "$repo_root"

PYTHONPATH="$repo_root/scripts" "$python_cmd" scripts/validate-config.py
PYTHONPATH="$repo_root/scripts" "$python_cmd" scripts/render-config.py

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

mkdir -p "$tmp_dir/certs" "$tmp_dir/http-certs" "$tmp_dir/config/certs" "$tmp_dir/config/http" "$tmp_dir/data"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$tmp_dir/certs/central-ca.key" \
  -out "$tmp_dir/certs/central-ca.crt" \
  -days 1 \
  -subj "/CN=test-central-ca" \
  -batch >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$tmp_dir/http-certs/server.key" \
  -out "$tmp_dir/http-certs/server.crt" \
  -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -batch >/dev/null 2>&1
openssl pkcs8 -topk8 -nocrypt \
  -in "$tmp_dir/http-certs/server.key" \
  -out "$tmp_dir/http-certs/server.pkcs8.key" >/dev/null 2>&1
cp "$tmp_dir/http-certs/server.crt" "$tmp_dir/http-certs/client-ca.crt"

cat > "$tmp_dir/test.env" <<'ENV'
CENTRAL_INGEST_URL=https://siem.example.com:5044/
CUSTOMER_FORWARDER_USERNAME=test-forwarder
CUSTOMER_FORWARDER_PASSWORD=test-password
CENTRAL_CA_CERT=/usr/share/logstash/config/certs/central-ca.crt
LS_JAVA_OPTS="-Xms512m -Xmx512m"
FORWARDER_MEM_LIMIT=1g
WINDOWS_HTTP_USERNAME=windows-forwarder
WINDOWS_HTTP_PASSWORD=test-http-password
ENV

env_file="${CUSTOMER_FORWARDER_ENV_FILE:-}"
env_root="$repo_root"
if [[ -z "$env_file" ]]; then
  if [[ -f .env ]]; then
    env_file="$repo_root/.env"
  else
    env_file="$tmp_dir/test.env"
    env_root="$tmp_dir"
  fi
fi

PYTHONPATH="$repo_root/scripts" "$python_cmd" scripts/validate-env.py \
  --root "$env_root" \
  --env-file "$env_file"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "docker unavailable; skipped customer forwarder live logstash config validation"
  exit 0
fi

cp config/pipelines.yml "$tmp_dir/config/pipelines.yml"
sed 's#^path.queue:.*#path.queue: /tmp/customer-forwarder-test-data/queue#' \
  config/logstash.yml > "$tmp_dir/config/logstash.yml"
printf 'path.data: /tmp/customer-forwarder-test-data\n' >> "$tmp_dir/config/logstash.yml"

image="$(awk '/^[[:space:]]*image:/ { print $2; exit }' docker-compose.yml)"
if [[ "$image" != *@sha256:* || "$image" == *"<resolved-image-digest>"* ]]; then
  echo "customer-forwarder image must be pinned by resolved @sha256 digest" >&2
  exit 1
fi

cat > "$tmp_dir/docker-compose.yml" <<YAML
services:
  customer-forwarder:
    image: $image
    environment:
      LS_JAVA_OPTS: "-Xms512m -Xmx512m"
      CENTRAL_INGEST_URL: https://siem.example.com:5044/
      CUSTOMER_FORWARDER_USERNAME: test-forwarder
      CUSTOMER_FORWARDER_PASSWORD: test-password
      CENTRAL_CA_CERT: /usr/share/logstash/config/certs/central-ca.crt
      WINDOWS_HTTP_USERNAME: windows-forwarder
      WINDOWS_HTTP_PASSWORD: test-http-password
    volumes:
      - $tmp_dir/config:/usr/share/logstash/config:ro
      - $repo_root/pipeline:/usr/share/logstash/pipeline:ro
      - $tmp_dir/data:/tmp/customer-forwarder-test-data
      - $tmp_dir/certs:/usr/share/logstash/config/certs:ro
      - $tmp_dir/http-certs:/usr/share/logstash/config/http:ro
YAML

docker compose --project-directory "$tmp_dir" -f "$tmp_dir/docker-compose.yml" run --rm --no-deps \
  customer-forwarder \
  logstash --path.settings /usr/share/logstash/config --config.test_and_exit

echo "customer forwarder logstash config passed"
