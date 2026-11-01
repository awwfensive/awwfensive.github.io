---
title: "Hackbot"
description: "Ongoing research into autonomous security testing, harness engineering, authorization boundaries, and evaluation."
---

*Ongoing research.*

Hackbot is my research effort into autonomous security testing. I’m interested in whether an offensive agent can investigate a system and produce findings another person can reproduce.

## Current state

I’m exploring harness design, agent permissions, evidence capture, and evaluation. Implementation details, a public release, and benchmark results are not available here yet.

## Architecture and workflow

The proposed workflow is to define the authorized scope, give the agent tools through a controlled harness, record its actions and observations, and evaluate its findings in a reproducible environment. This is a research direction; it is not a list of implemented capabilities.

## Authorization boundaries

The harness needs to enforce target scope and tool permissions independently of the model. Open questions include scope expansion through redirects, delegated permissions, connector access, and when an uncertain action should require operator review.

## Evaluation and experiments

Planned experiments focus on confirmed findings, false positives, boundary violations, and reproducibility. Any published result should include the target set, model and harness versions, operator interventions, resource budget, and known limitations.

There are no public experiment results yet.

## Research log

- **1 November 2026:** Added this overview of the research direction and open questions.

## Next questions

- What evidence is sufficient to reproduce an agent-discovered finding?
- Which feedback structures improve investigation quality?
- How much apparent autonomy depends on operator help or benchmark design?
- How should failed hypotheses and scope violations affect evaluation?

[Current focus](/now/) · [Research notebook](/notes/)
