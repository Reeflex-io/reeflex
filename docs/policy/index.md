---
title: Policy & customization
description: >-
  The entire decision policy is one Rego file. This section links to the
  guide for reading it, changing it, and testing your change before you ship it.
---

# Policy & customization

`reeflex-core` evaluates exactly one Rego file,
[`reeflex-core/policy/reeflex.rego`](https://github.com/Reeflex-io/reeflex/blob/main/reeflex-core/policy/reeflex.rego),
backed by one test file. There is no plugin API, no DSL, no hidden config
layer — you read the rules, you edit the rules, `opa test` tells you whether
you broke anything.

- [Adapt the policy](../policy-guide.md) — three levels of change, from
  flipping one constant to adding a new rule end-to-end to replacing the
  whole policy directory, with every example verified against a real
  `opa test` run.
- [Why Reeflex (HIL / HOTL / AIL)](../why-reeflex.md#ail) — the canonical
  definition of who may resolve a hold, and why the base policy is a floor,
  not a ceiling.
