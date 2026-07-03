# Reeflex SIEM Integration

<!-- doc-version: siem-v1.0 | source: reeflex-core/app/telemetry.py @ CORE_VERSION 0.1.3 -->

Every `/v1/decide` call can emit a structured syslog event to a SIEM collector.
The emitter is **disabled by default** and is fire-and-forget: it never blocks
the decision gate.

---

## 1. Quickstart

Set three environment variables and restart the container:

```
REEFLEX_SYSLOG_ENABLED=true
REEFLEX_SYSLOG_ADDRESS=collector:514
REEFLEX_SYSLOG_PROTOCOL=udp
```

To verify reception before wiring a full SIEM, open a UDP listener on the
collector host and fire one decision:

```bash
# On the collector host
nc -luk 514

# In another terminal — trigger any decision to generate an event
curl -s -X POST http://localhost:8080/v1/decide \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $REEFLEX_API_TOKEN" \
  -d '{"session_id":"test-001","agent_id":"agent-a","ability":"wordpress/post.create",
       "verb":"create","axes":{"reversibility":"reversible",
       "blast_radius":"single","externality":"internal"},
       "magnitude":{"count":1},"environment":"staging","on_behalf_of":"alice"}'
```

Expected line received on `nc` (JSON format, one RFC 5424 syslog line):

```
<134>1 2026-07-03T12:00:00Z my-host reeflex 42 decision - {"ts":"2026-07-03T12:00:00Z","event":"decision","verdict":"allow","rule_id":"reeflex.core/R1_allow","verb":"create","ability":"wordpress/post.create","axes":{"reversibility":"reversible","blast_radius":"single","externality":"internal"},"magnitude_count":1,"session_id":"test-001","agent_id":"agent-a","on_behalf_of":"alice","environment":"staging","mode":"enforce","decision_latency_ms":3,"reason":"","reeflex_version":"0.1.3","epoch_ms":1751543200000}
```

All values above are synthetic examples. Real values depend on your envelope and
policy configuration.

---

## 2. Event reference

### 2.1 Decision event — JSON schema

Emitted once after every `/v1/decide` response, just before returning to the
caller. Fields sourced from `DECISION_EVENT_FIELDS` in `telemetry.py`.

| Field | Type | Meaning |
|---|---|---|
| `ts` | string (RFC3339 UTC) | Timestamp of the decision |
| `event` | string | Always `"decision"` |
| `verdict` | string | `allow` \| `deny` \| `require_approval` |
| `rule_id` | string | Fired OPA rule identifier |
| `verb` | string | Action verb (`read`, `delete`, `execute`, …) |
| `ability` | string | Fully-qualified ability name (`namespace/verb`) |
| `axes.reversibility` | string | Reversibility axis value |
| `axes.blast_radius` | string | Blast-radius axis value |
| `axes.externality` | string | Externality axis value |
| `magnitude_count` | integer | `magnitude.count` integer from the envelope |
| `session_id` | string | Agent session identifier |
| `agent_id` | string | Agent identifier |
| `on_behalf_of` | string | User the agent acts on behalf of |
| `environment` | string | Target environment (`production`, `staging`, …) |
| `mode` | string | Enforcement mode: `enforce` \| `observe` |
| `decision_latency_ms` | integer | Wall-clock ms between start and end of `decide.process()` |
| `reeflex_version` | string | reeflex-core engine version string |

Additional fields present in the wire message (not in `DECISION_EVENT_FIELDS`
but emitted by the engine):

| Field | Type | Meaning |
|---|---|---|
| `epoch_ms` | integer | Decision timestamp as milliseconds since Unix epoch (used by CEF `rt`) |
| `reason` | string | Human-readable reason from OPA (may be empty string) |

#### Sample JSON event

```json
{
  "ts": "2026-07-03T12:00:00Z",
  "event": "decision",
  "verdict": "deny",
  "rule_id": "reeflex.core/R3_deny",
  "verb": "delete",
  "ability": "wordpress/post.delete",
  "axes": {
    "reversibility": "irreversible",
    "blast_radius": "systemic",
    "externality": "external"
  },
  "magnitude_count": 50,
  "session_id": "sess-abc123",
  "agent_id": "agent-writer-01",
  "on_behalf_of": "bob",
  "environment": "production",
  "mode": "enforce",
  "decision_latency_ms": 7,
  "reason": "irreversible + systemic + production",
  "reeflex_version": "0.1.3",
  "epoch_ms": 1751543200000
}
```

All values are synthetic examples.

---

### 2.2 CEF format

When `REEFLEX_SYSLOG_FORMAT=cef`, the MSG portion of the syslog frame is a
CEF:0 string:

```
CEF:0|Reeflex|reeflex-core|<version>|<rule_id>|<verdict>|<severity>|<extensions>
```

The extension mapping below is sourced from `CEF_MAPPING_TABLE` in
`telemetry.py`. Label fields (`cs1Label`, `cs2Label`, etc.) are emitted as
literal strings alongside their value field.

| CEF key | CEF label / note | Reeflex field |
|---|---|---|
| `rt` | timestamp ms | epoch_ms of the decision |
| `act` | action verb | `verb` |
| `suser` | subject user | `on_behalf_of` |
| `cs1` | session_id | `session_id` |
| `cs1Label` | label for cs1 | literal `'session_id'` |
| `cs2` | agent_id | `agent_id` |
| `cs2Label` | label for cs2 | literal `'agent_id'` |
| `cs3` | reversibility | `axes.reversibility` |
| `cs3Label` | label for cs3 | literal `'reversibility'` |
| `cs4` | blast_radius | `axes.blast_radius` |
| `cs4Label` | label for cs4 | literal `'blast_radius'` |
| `cs5` | externality | `axes.externality` |
| `cs5Label` | label for cs5 | literal `'externality'` |
| `cs6` | environment | target environment |
| `cs6Label` | label for cs6 | literal `'environment'` |
| `cn1` | magnitude_count | `magnitude.count` integer |
| `cn1Label` | label for cn1 | literal `'magnitude_count'` |
| `cn2` | decision_latency_ms | decision latency in ms |
| `cn2Label` | label for cn2 | literal `'decision_latency_ms'` |
| `msg` | reason | human-readable reason from OPA |
| `flexString1` | mode | `enforce` \| `observe` |
| `flexString1Label` | label | literal `'mode'` |

The `rule_id` appears as the CEF **EventID** (4th pipe-delimited header field).
The `verdict` is the CEF **Name** (5th field).

#### Sample CEF line

```
CEF:0|Reeflex|reeflex-core|0.1.3|reeflex.core/R3_deny|deny|3|rt=1751543200000 act=delete suser=bob cs1=sess-abc123 cs1Label=session_id cs2=agent-writer-01 cs2Label=agent_id cs3=irreversible cs3Label=reversibility cs4=systemic cs4Label=blast_radius cs5=external cs5Label=externality cs6=production cs6Label=environment cn1=50 cn1Label=magnitude_count cn2=7 cn2Label=decision_latency_ms msg=irreversible + systemic + production flexString1=enforce flexString1Label=mode
```

All values are synthetic examples.

---

### 2.3 Severity map (RFC 5424)

| Verdict / event type | RFC 5424 severity code | Label |
|---|---|---|
| `allow` | 6 | informational |
| `require_approval` | 4 | warning |
| `deny` | 3 | error |
| `lifecycle` | 5 | notice |
| `kill_switch` | 2 | critical |

The PRI byte in the syslog frame is `facility_code * 8 + severity_code`.
Default facility is `local0` (code 16), so a `deny` event has PRI `16*8+3 = 131`,
i.e. `<131>`.

---

### 2.4 Additional event types

**lifecycle** — emitted on engine start and stop. Shape:

```json
{"ts": "2026-07-03T12:00:00Z", "event": "lifecycle", "phase": "start", "reeflex_version": "0.1.3"}
```

MSGID in the syslog header is `lifecycle`. Severity: `5` (notice).

**kill_switch** — designed and wired; arrives with Phase 1. When the
kill-switch enforcement module ships it will call `emit_kill_switch()`, which
emits the following shape with severity `2` (critical) and MSGID `kill_switch`:

| Field | Type | Meaning |
|---|---|---|
| `ts` | string (RFC3339 UTC) | Timestamp of the kill-switch flip |
| `event` | string | Always `"kill_switch"` |
| `action` | string | `flipped` \| `cleared` \| `queried` |
| `reason` | string | Human-readable reason for the flip |
| `reeflex_version` | string | reeflex-core engine version string |

A kill-switch event is severity critical (2) and should trigger an on-call
alert in any properly configured SIEM.

---

## 3. Consuming from your platform

Reeflex emits standard RFC 5424 syslog over UDP, TCP, or TLS. The guides below
show input/receiver configuration and one example search per platform. No
Reeflex-specific dashboards or detection packs are shipped — you own the
alerting logic.

### Splunk

Add a UDP or TCP syslog input in Splunk Web (Settings > Data inputs > UDP/TCP):

- Source type: `syslog`
- Port: `514` (or your chosen port)
- Index: e.g. `reeflex`

For JSON format, also add a `TRANSFORMS` entry to extract the JSON blob from the
MSG field:

```ini
# props.conf
[syslog]
TRANSFORMS-reeflex = reeflex_json_extract

# transforms.conf
[reeflex_json_extract]
REGEX = \} (\{.+\})$
FORMAT = _raw::$1
SOURCE_KEY = _raw
```

Example SPL search (find all `deny` decisions):

```spl
index=reeflex sourcetype=syslog verdict=deny | table ts, agent_id, ability, axes.reversibility
```

### IBM QRadar

1. Log Source Type: **Syslog**
2. Protocol: UDP or TCP (use TCP for QRadar > 7.5 to avoid datagram loss)
3. Log Source Identifier: `reeflex-core`
4. Parse the MSG JSON body using a **Custom Log Source Extension (LSX)**
   pointing to the `event` and `verdict` fields.

Example AQL query (require_approval events in the last hour):

```sql
SELECT "sourceip", UTF8(payload) AS raw, "starttime"
FROM events
WHERE LOGSOURCETYPENAME(devicetype) = 'Syslog'
  AND UTF8(payload) LIKE '%"verdict":"require_approval"%'
LAST 1 HOURS
```

### Wazuh

Add a remote syslog input in `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>REEFLEX_CORE_IP/32</allowed-ips>
  </remote>
</ossec_config>
```

Then add a custom decoder in `/var/ossec/etc/decoders/reeflex.xml`:

```xml
<decoder name="reeflex-decision">
  <prematch>reeflex.*"event":"decision"</prematch>
  <regex>"verdict":"(\w+)".*"agent_id":"(\S+)"</regex>
  <order>verdict, agent_id</order>
</decoder>
```

Example alert rule (deny events create a level-10 alert):

```xml
<rule id="100500" level="10">
  <decoded_as>reeflex-decision</decoded_as>
  <match>verdict=deny</match>
  <description>Reeflex: action denied by policy</description>
</rule>
```

### FortiSIEM

1. Admin > Device Support > Event Pulling: add a **Syslog** listener on the
   collector port.
2. Create a Parser under **Analytics > Rules**: extract `verdict`, `agent_id`,
   `session_id` from the JSON MSG field using **JSON Path** attribute mapping.
3. Map `reeflex-core` to a new Device Type `Reeflex Core Engine`.

Example incident rule query:

```
eventType = "reeflex-decision" AND verdict = "deny"
GROUP BY agent_id
HAVING COUNT(*) > 10 IN 5 MINUTES
```

### Graylog

1. Create a **Syslog UDP** or **Syslog TCP** input (System > Inputs).
2. Enable **Store full message** to retain the JSON body.
3. Add a **JSON extractor** on the `message` field to auto-parse all JSON keys
   as Graylog fields.

Example search (all decisions for a specific agent):

```
event:decision AND agent_id:agent-writer-01
```

### Grafana Loki (promtail syslog)

Add a syslog listener block to `promtail.yaml`:

```yaml
scrape_configs:
  - job_name: reeflex_syslog
    syslog:
      listen_address: 0.0.0.0:514
      label_structured_data: true
      labels:
        job: reeflex-core
    pipeline_stages:
      - json:
          expressions:
            verdict: verdict
            agent_id: agent_id
            environment: environment
      - labels:
          verdict:
          environment:
```

Example LogQL query (deny rate per minute):

```logql
rate({job="reeflex-core", verdict="deny"}[1m])
```

### Datadog

Enable the **Syslog** integration or use the Datadog Agent `syslog` listener.
In `datadog.yaml`:

```yaml
logs:
  - type: udp
    port: 514
    service: reeflex-core
    source: syslog
    log_processing_rules:
      - type: multi_line
        name: reeflex_json
        pattern: '^\{' 
```

Example Logs query (approval-required events in production):

```
service:reeflex-core verdict:require_approval environment:production
```

### Logstash (native syslog input)

Use the built-in `syslog` input plugin — no additional config on the Reeflex
side:

```ruby
input {
  syslog {
    port => 514
    type => "reeflex"
  }
}

filter {
  if [type] == "reeflex" {
    json {
      source => "message"
      target => "reeflex"
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://es-host:9200"]
    index => "reeflex-%{+YYYY.MM.dd}"
  }
}
```

Example Kibana KQL search:

```
reeflex.verdict: "deny" and reeflex.environment: "production"
```

### Filebeat (tail the audit JSONL)

For deployments where syslog is not available, Filebeat can tail the audit log
directly. The audit JSONL is the authoritative record — syslog and JSONL carry
the same decision data.

Audit log path (default, override with `REEFLEX_AUDIT_LOG`):

- Bare Python: `./audit/decisions.jsonl`
- Docker / reeflex-wordpress plugin: typically
  `wp-content/uploads/reeflex/audit/decisions.jsonl`
  (exact path set by the adapter)

```yaml
filebeat.inputs:
  - type: filestream
    id: reeflex-audit
    paths:
      - /var/lib/reeflex/audit/decisions.jsonl
    parsers:
      - ndjson:
          target: reeflex
          overwrite_keys: true

output.logstash:
  hosts: ["logstash-host:5044"]
```

No configuration required on the Reeflex side — this is a read-only tail of an
existing file.

### Fluentd (tail the audit JSONL)

Same approach as Filebeat — tail the JSONL file, no Reeflex config needed:

```apache
<source>
  @type tail
  path /var/lib/reeflex/audit/decisions.jsonl
  pos_file /var/log/td-agent/reeflex-audit.pos
  tag reeflex.audit
  <parse>
    @type json
  </parse>
</source>

<match reeflex.audit>
  @type elasticsearch
  host es-host
  port 9200
  index_name reeflex_audit
</match>
```

### Forwarding to Kafka

A Fluentd, Logstash, or Vector sidecar can bridge Reeflex syslog or JSONL
events to a Kafka topic with no changes to reeflex-core. Example using
Fluentd's `kafka2` output plugin:

```apache
<source>
  @type syslog
  port 514
  bind 0.0.0.0
  tag reeflex.syslog
  <parse>
    @type json
  </parse>
</source>

<match reeflex.syslog>
  @type kafka2
  brokers kafka-broker:9092
  default_topic reeflex-decisions
  <format>
    @type json
  </format>
</match>
```

A native Kafka emitter built into reeflex-core is not planned — it would add an
external dependency to a stdlib-only engine. If real enterprise demand emerges,
a separate sidecar process (not a core module) is the correct architecture.

---

## 4. The invariant

> **Fail-closed for decisions, fail-open for telemetry.**

Telemetry is fire-and-forget:

- A bounded in-memory queue (1 000 messages) holds outbound syslog messages.
- One background daemon thread drains the queue and does all socket I/O.
- `emit()` calls `queue.put_nowait()` inside a `try/except queue.Full` and
  returns immediately. It **never** raises into `/v1/decide`.
- Socket errors, DNS failures, slow or unreachable endpoints, TLS handshake
  failures, and reconnection delays are all swallowed in the worker thread.
- When the queue is full, the event is dropped and the module-level
  `dropped_events` counter is incremented. The counter is readable via
  `get_dropped_count()` and is logged at engine shutdown.
- When `REEFLEX_SYSLOG_ENABLED` is `false` (the default), no thread is spawned
  and every `emit()` call is a one-line no-op — zero overhead on the decision
  path.

The **audit JSONL** remains the authoritative record of every decision.
Syslog telemetry is a real-time observability feed, not a replacement for the
audit log.

---

<!-- END docs/siem.md -->
