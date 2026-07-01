# Windows HTTP JSON Sender Examples

The forwarder exposes HTTPS JSON inputs for Windows AD and Sysmon-shaped events.
It does not expose the native Beats protocol. A production deployment can use
Winlogbeat or an internal Windows collector to produce JSON events and post them
to:

- `https://<forwarder-host>:8081/` for `windows-ad`
- `https://<forwarder-host>:8082/` for `windows-sysmon`

Each request must include:

- Basic auth using `WINDOWS_HTTP_USERNAME` and `WINDOWS_HTTP_PASSWORD`
- a client certificate trusted by `customer-forwarder/http-certs/client-ca.crt`
- JSON shaped like the fixtures in `../../test/fixtures/`

Use `post-winlogbeat-json.ps1` only as a connectivity and handoff example.
Production collection should use a managed Windows logging agent or service
account with certificate rotation.
