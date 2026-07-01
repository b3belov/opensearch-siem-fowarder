# Customer Forwarder

Customer Forwarder is a static Logstash package that runs in customer
infrastructure. It collects first-stage logs, normalizes supported sources, uses
a local persistent queue, and forwards JSON events to the central SIEM
`ingest-edge` endpoint.

## Supported `siem.source_id` Values

The controlled source catalog is copied into `config/source-catalog.yml`.
Version one supports:

- `generic-syslog`
- `windows-ad`
- `windows-sysmon`

The local `config/forwarder.yml` source keys must match these IDs exactly.
If validation reports an unknown source ID, compare `config/forwarder.yml` with
`config/source-catalog.yml`. While this folder lives in the main repo,
`config/source-catalog.yml` must match `../source-catalog/sources.yml`.
`config/source-catalog.lock` records the source repo commit, copied file
checksums, and supported IDs for customer handoff.

## Inputs

| `siem.source_id` | Protocol | Default port | Sender expectation | Smoke test |
|---|---:|---:|---|---|
| `generic-syslog` | syslog TCP/UDP | `5514` | RFC3164/RFC5424 syslog from devices, Linux, or appliances | `logger -n <forwarder-host> -P 5514 "siem test"` |
| `windows-ad` | HTTPS JSON | `8081` | HTTPS POST JSON shaped like Winlogbeat Windows Security/AD events with Basic auth and client certificate; this is not the native Beats protocol | `curl --cacert http-certs/client-ca.crt --cert http-certs/client.crt --key http-certs/client.key -u "$WINDOWS_HTTP_USERNAME:$WINDOWS_HTTP_PASSWORD" -H 'Content-Type: application/json' --data @test/fixtures/windows-ad.json https://<forwarder-host>:8081/` |
| `windows-sysmon` | HTTPS JSON | `8082` | HTTPS POST JSON shaped like Winlogbeat Sysmon events with Basic auth and client certificate; this is not the native Beats protocol | `curl --cacert http-certs/client-ca.crt --cert http-certs/client.crt --key http-certs/client.key -u "$WINDOWS_HTTP_USERNAME:$WINDOWS_HTTP_PASSWORD" -H 'Content-Type: application/json' --data @test/fixtures/windows-sysmon.json https://<forwarder-host>:8082/` |

## Configure

Copy `.env.example` to `.env` and set:

```text
CENTRAL_INGEST_URL=https://siem.example.com:5044/
CUSTOMER_FORWARDER_USERNAME=<central credential id>
CUSTOMER_FORWARDER_PASSWORD=<central credential password>
CENTRAL_CA_CERT=/usr/share/logstash/config/certs/central-ca.crt
LS_JAVA_OPTS="-Xms512m -Xmx512m"
FORWARDER_MEM_LIMIT=1g
WINDOWS_HTTP_USERNAME=windows-forwarder
WINDOWS_HTTP_PASSWORD=<windows http collector password>
```

Place the central CA certificate at:

```text
customer-forwarder/certs/central-ca.crt
```

Place the Windows HTTP collector certificate material at:

```text
customer-forwarder/http-certs/server.crt
customer-forwarder/http-certs/server.pkcs8.key
customer-forwarder/http-certs/client-ca.crt
```

The Windows HTTP sender must trust `server.crt`, authenticate with
`WINDOWS_HTTP_USERNAME` and `WINDOWS_HTTP_PASSWORD`, and present a client
certificate signed by `client-ca.crt`.

Edit `config/forwarder.yml` to choose enabled source inputs and ports.

## Validate And Render

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r requirements.lock
PYTHONPATH=scripts python scripts/validate-config.py
PYTHONPATH=scripts python scripts/render-config.py
PYTHONPATH=scripts python scripts/validate-env.py --env-file .env
```

## Run

```bash
docker compose up -d
docker compose logs -f customer-forwarder
```

Runtime state is stored under `data/` and must be on durable disk. The default
persistent queue size is `8gb`; validation requires enough free disk for
`queue.max_bytes + dlq_max_bytes` plus 20% headroom.

## Security

Protect collector ports `5514`, `8081`, and `8082` with customer-network
firewall rules, VPN boundaries, or source ACLs. Syslog senders are network
trusted in v1, so hosts that can reach `5514` can submit syslog events that the
forwarder sends with the customer's central credential. Windows HTTP JSON inputs
must use TLS, Basic auth, client certificate authentication, and a 1 MB request
body limit. Do not expose any collector port directly to the public internet.

## Performance

Version one forwards one JSON event per HTTPS request to central `ingest-edge`.
This keeps central compatibility simple. For high-volume Sysmon sources, monitor
Logstash queue depth and run the optional smoke test against a running local
forwarder:

```bash
PYTHONPATH=scripts python scripts/load-smoke.py \
  --url https://localhost:8082/ \
  --password "$WINDOWS_HTTP_PASSWORD" \
  --ca-cert http-certs/client-ca.crt \
  --client-cert http-certs/client.crt \
  --client-key http-certs/client.key \
  --count 100
```

The smoke helper reads `http://127.0.0.1:9600/_node/stats/pipelines` by default
and fails if the output pipeline does not advance or if queue depth grows
unexpectedly. Use `--skip-monitor` only when the Logstash monitoring API is not
available.

## Central Handoff And First-Run Proof

The central SIEM owner must provide the customer with:

- the exact customer credential ID matching `^[a-z][a-z0-9-]{1,40}$`
- the credential password
- the central `ingest-edge` HTTPS URL
- the central CA certificate
- the supported `source_id` list and catalog lock generated with this package

Before handoff is considered complete, run:

```bash
PYTHONPATH=scripts python scripts/validate-config.py
PYTHONPATH=scripts python scripts/validate-env.py --env-file .env
docker compose up -d
PYTHONPATH=scripts python scripts/load-smoke.py \
  --password "$WINDOWS_HTTP_PASSWORD" \
  --ca-cert http-certs/client-ca.crt \
  --client-cert http-certs/client.crt \
  --client-key http-certs/client.key \
  --count 10
```

Capture `customer forwarder config valid`, `customer forwarder environment
valid`, container health, and successful load-smoke output as the first-run proof.
