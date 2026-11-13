---
title: Operations
description: >-
  Running reeflex-core day to day: observability into every decision, and
  exporting that record to the SIEM your team already watches.
---

# Operations

Every `/v1/decide` call is fail-closed for the decision itself and
fail-open for telemetry: a broken or unreachable observability sink never
blocks a decision, and a broken or ambiguous policy never opens one.

- [SIEM export](../siem.md) — the structured syslog event Reeflex can emit
  for every decision (JSON or CEF), the severity map, and worked
  configuration examples for Splunk, QRadar, Wazuh, FortiSIEM, Graylog,
  Loki, Datadog, Logstash, Filebeat, Fluentd, and Kafka.
- [Evidence connector](../connector.md) — the published container that ships
  each decision from your engine's audit log to the Reeflex portal as signed
  evidence: configuration, what it sends and does not send, and how to verify
  delivery.
