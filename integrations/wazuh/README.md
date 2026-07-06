# Consuming Reeflex in Wazuh

> **Community example, unmaintained.** This directory ships *parsing* — a
> decoder, one base rule, and one example dashboard — so you can watch Reeflex
> gate decisions in [Wazuh](https://wazuh.com/). It is a starting point, not a
> maintained product. What you build on top of it is yours.

Reeflex-core emits every decision as **standard syslog** (RFC 5424, JSON payload)
via its built-in SIEM telemetry — **no custom connector, no agent, no plugin**.
Wazuh ingests it with the decoder + rule here.

## 1. Emit decisions from reeflex-core

Set these environment variables on your reeflex-core deployment and restart it:

| Variable | Value |
|---|---|
| `REEFLEX_SYSLOG_ENABLED` | `true` |
| `REEFLEX_SYSLOG_ADDRESS` | `<wazuh-manager-host>:514` |
| `REEFLEX_SYSLOG_PROTOCOL` | `tcp` (or `udp` / `tls`) |
| `REEFLEX_SYSLOG_FORMAT` | `json` |

Telemetry is **fire-and-forget** — it never blocks or breaks `/v1/decide`.
Behind a reverse proxy, reeflex-core records the caller's IP from
`X-Forwarded-For` and emits it as `srcip` (see GeoIP below).

## 2. Receive syslog on the Wazuh manager

Add a remote syslog listener to `/var/ossec/etc/ossec.conf` (skip if you already
have one), then restart the manager:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>YOUR_REEFLEX_HOST/32</allowed-ips>
</remote>
```

## 3. Install the decoder + rule

```bash
cp reeflex-decoder.xml /var/ossec/etc/decoders/
cp reeflex-rules.xml   /var/ossec/etc/rules/
systemctl restart wazuh-manager
```

Verify with logtest (paste a sample line, Ctrl-D):

```bash
/var/ossec/bin/wazuh-logtest
```

The decoder uses a cheap `program_name`-style prematch and Wazuh's **native
JSON_Decoder**, so all fields decode with no per-field regex:

`verdict`, `rule_id`, `verb`, `ability`, `axes.reversibility/blast_radius/externality`,
`magnitude_count`, `session_id`, `agent_id` (the adapter/module, e.g.
`agent:wordpress`), `namespace` (the backend), `target_ref`, `params.*` (the exact
command), `environment`, `mode`, `decision_latency_ms`, `reason`, and `srcip`.

The base rule (`100200`, level 3) fires on every decoded event. It is a base
"Reeflex event" rule — add your own higher-severity rules for `deny` /
`require_approval` if you want verdict-based alerting.

## 4. Import the CISO/SOC dashboard

`reeflex-ciso-dashboard.ndjson` is an example dashboard scoped to Reeflex events
(`rule.id: 100200`): verdict breakdown, decisions-over-time, top rules, holds
pending, blast-radius distribution, module (agent) breakdown, and recent denies.

Wazuh Dashboard → **Stack Management → Saved Objects → Import** (or the API):

```bash
curl -sk -u <user>:<pass> -H 'osd-xsrf:true' \
  -X POST 'https://<dashboard>/api/saved_objects/_import?overwrite=true' \
  --form file=@reeflex-ciso-dashboard.ndjson
```

It references the standard `wazuh-alerts-*` index pattern.

## 5. GeoIP (optional)

The caller IP lands in `data.srcip`. To geolocate it, configure a
[GeoLite2 database in Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/geolocation.html)
— Wazuh then enriches alerts that carry `srcip`. Private/internal source IPs are
not geolocated.

---
*Tested against Wazuh 4.14.x + reeflex-core with SIEM telemetry. Community
example — no support guarantee.*
