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

### Initial setup from a wizard handoff

Accept a handoff only from your trusted SIEM operator. The
`SIEM-FORWARDER-V1:` line carries executable Logstash configuration. Base64
provides transport encoding. Keep the handoff and the separately delivered
password private.

Use the Python dependencies from **Validate And Render**, then prepare the
repository's existing Compose secret file.

```bash
(umask 077; touch .env)
chmod 600 .env
${EDITOR:-vi} .env
```

Set `CUSTOMER_FORWARDER_PASSWORD` in that file using the password from the
operator. Ledger mode gets its central destination and username from the
handoff. Run the installer, paste the complete line at its prompt, and press
Enter.

```bash
.venv/bin/python scripts/configure-forwarder.py
```

For a saved handoff, either invocation below reads the ledger without putting
it in the command line.

```bash
.venv/bin/python scripts/configure-forwarder.py --file handoff.txt
.venv/bin/python scripts/configure-forwarder.py < handoff.txt
```

The installer accepts up to 4 MiB of input and 8 MiB of decompressed archive
data. It stores private revisions in `data/forwarder-handoff/` and mounts
`data/logstash/` as Logstash's data directory. With Docker available, it checks
queue mount permissions and validates the staged configuration with the pinned
Logstash image before switching the active Compose file. If Docker is
unavailable, rerun the installer on the deployment host before starting the
service. The installer stops if it finds an incomplete installation or a manual
deployment whose customer identity it cannot verify.

The installer retains the original pipeline with each revision. The running
copy uses the pinned HTTP output plugin's `cacert` setting for the supplied CA
and keeps full TLS verification enabled.

### Apply a regenerated ledger

Run the same installer with the regenerated ledger. It compares the customer
slug and HTTP username against the active pipeline and stops if either differs
or cannot be verified. The installer reuses `CUSTOMER_FORWARDER_PASSWORD` from
the existing `.env` binding. If the binding is missing, restore the existing
password to the protected file before retrying. Customer changes and credential
rotation are separate operator workflows.

Review the listed settings, endpoint, listener, and CA changes, then answer
`y` to confirm. For a noninteractive run, review the output first and rerun
with `--yes` to confirm. An identical configuration reports that it is already
current, even if the handoff README changed.

Updates retain the active data mount and its queued events, including mounts
from earlier ledger installations. They also keep unrelated Compose settings.
The installer prints the path to a protected snapshot of the previous Compose
file, which still references the retained configuration files. To roll back,
reapply the earlier ledger with the same password binding. If the ledger is
unavailable, restore the saved Compose snapshot to
`data/forwarder-handoff/compose.yml` while the installer is idle, then run the
printed reload command.

### Start, reload, and confirm delivery

Run the start or reload command printed by the installer. Then check service
health using the ledger Compose file.

```bash
docker compose --project-directory . -f data/forwarder-handoff/compose.yml ps
```

From an authorized Linux sender, use a syslog port and protocol printed by the
installer. This example uses TCP and the util-linux version of `logger`.

```bash
read -r -p 'Forwarder host: ' forwarder_host
read -r -p 'Published syslog TCP port: ' syslog_port
probe_id="siem-handoff-$(date -u +%Y%m%dT%H%M%SZ)-$$"
logger --rfc3164 --tcp --server "$forwarder_host" --port "$syslog_port" --tag siem-handoff "$probe_id"
printf 'Send this probe ID to the central SIEM operator: %s\n' "$probe_id"
```

For a UDP-only listener, use `--udp` and its published port. Give the SIEM
operator the probe ID and customer identifier. Ask them to confirm the event
arrived under the expected customer and source ID.

### Disconnect the ledger forwarder

On the deployment host, use the same Docker context that runs the forwarder.
Run the following command and confirm the removal. Use `--yes` to confirm
noninteractively.

```bash
.venv/bin/python scripts/configure-forwarder.py --disconnect
```

Disconnect stops and removes the ledger-managed container and deletes its
active Compose file, staged configuration, and rollback copies. It removes
`CUSTOMER_FORWARDER_PASSWORD` from the shared `.env` and preserves the other
entries, persistent queues, and any original handoff file you saved outside
the installer state. It requires Docker access to check the
container's ownership and leaves manual deployments alone. If cleanup is
interrupted, run the disconnect command again to finish.

Before onboarding again, handle any retained queue data separately. The
installer refuses to attach a new ledger to leftover queue state whose
customer it cannot verify.

### Configure manually

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

Install these dependencies for either workflow.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install --require-hashes -r requirements.lock
```

For manual configuration, validate and render the source catalog and settings.

```bash
PYTHONPATH=scripts python scripts/validate-config.py
PYTHONPATH=scripts python scripts/render-config.py
PYTHONPATH=scripts python scripts/validate-env.py --env-file .env
```

## Run the manual configuration

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

## Manual Handoff And First-Run Proof

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
