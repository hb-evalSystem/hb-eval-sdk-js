# hb-eval-sdk-js

Operational reliability for agentic AI, for Node.js.

Measures how an agent behaves **while it runs** — not whether it finished, but
whether it stayed reliable getting there — and stops it when resilience
collapses.

```bash
npm install hb-eval-sdk-js
```

Node 18+. No runtime dependencies.

---

## Usage

```ts
import { HBEvalClient } from 'hb-eval-sdk-js'

const client = new HBEvalClient({
  apiKey: process.env.HBEVAL_API_KEY!,
  aesKey: process.env.HBEVAL_AES_KEY!,
  signingSecret: process.env.HBEVAL_SIGNING_SECRET!,
})

await client.withMonitor(
  {
    agentId: 'support-agent',
    haltPolicy: { metric: 'frr', below: 0.5, forSteps: 3 },
  },
  async (session) => {
    for (const step of await agent.run(task)) {
      session.recordStep({
        action: step.name,
        success: step.ok,
        hadFault: step.faulted,
        recoveredIntentionally: step.deliberateRecovery,  // null if N/A
        traceable: step.hasReasoning,
      })

      if (session.shouldHalt) {
        console.warn(session.haltReason)
        break
      }
    }
  },
)
```

Credentials come from **Dashboard → Agents** after creating an agent.

---

## What it measures

| Metric | Meaning |
|---|---|
| **PEI** | Planning efficiency — is the plan holding, or being redone? |
| **FRR** | Failure resilience — of the steps where a fault was present, how many still completed? |
| **IRS** | Intentional recovery — was the recovery reasoned, or a blind retry? |
| **TI** | Traceability — can each step's decision be followed? |
| **CSI** | Consistency across runs — needs repeated runs, so `null` within one session |

### `null` means unmeasured, and never zero

`FRR` before any fault has occurred, `IRS` with no recovery judgement, `CSI`
inside a single session: these are `null`, all the way to the wire.

Reporting them as `0` would claim a measured failure on a dimension nothing
examined — and a chart or a gate reading that zero would draw the wrong
conclusion loudly.

---

## Safe Halt

```ts
haltPolicy: { metric: 'frr', below: 0.5, forSteps: 3 }
```

**Sustained, not instantaneous.** One bad step is noise, and a guard that fires
on noise gets switched off within a week.

**Cooperative, not forced.** Nothing is killed mid-step — that is how
transactions end up half-applied. The session raises `shouldHalt`; your loop
decides how to stop.

**Off unless configured.** No `haltPolicy` means observation only. Stopping
somebody's agent is not a capability anyone should acquire by upgrading a
library.

The decision is recorded in full — metric, value, floor, consecutive steps, and
the policy verbatim — so a halt stays explainable after the fact and
reproducible against the rule that caused it:

```ts
session.haltRecord
// { metric: 'frr', metricValue: 0, threshold: 0.5,
//   consecutiveSteps: 3, stepIndex: 2,
//   policy: { metric: 'frr', below: 0.5, forSteps: 3 },
//   reason: 'FRR stayed below 0.5 for 3 consecutive steps',
//   triggerSource: 'policy', occurredAt: 1753992000 }
```

---

## Cost

Monitoring must not become the problem it was installed to detect, so its own
overhead is measured and published rather than asserted:

```ts
session.overheadStats
// { samples: 50000, p50Ms: 0.0006, p95Ms: 0.0021,
//   p99Ms: 0.0036, maxMs: 1.42, totalMs: 78.9, estimated: true }
```

Measured at **0.0006 ms per step at p50**, flat from 100 steps to 50,000.
Metrics come from running tallies rather than a rescan, so the cost does not
grow with the length of the run.

`estimated` says whether the percentiles are exact or drawn from a bounded
reservoir, so a reader never has to guess.

---

## Compatibility

The wire protocol is verified against the Python SDK by round-trip: ciphertext
produced here is decrypted by the Gateway's own code, and signatures computed
in both languages are compared byte for byte, including Unicode and nested
payloads.

Metrics are verified the same way — the same scenario through both
implementations must produce identical numbers, and does.

## Scope

This release covers the protocol and live monitoring: what a JavaScript agent
needs in order to be measured at all.

The fault-injection battery, the policy engine, OpenTelemetry auto-derivation
and the CI gate remain Python-only for now. A thin client whose crypto is
proven against the Gateway is worth more than a broad one whose is not.

- Python SDK: [`hb-eval-sdk`](https://pypi.org/project/hb-eval-sdk/)
- Documentation: [hbeval.com/docs](https://hbeval.com/docs)
- Status: [hbeval.com/status](https://hbeval.com/status)

MIT
