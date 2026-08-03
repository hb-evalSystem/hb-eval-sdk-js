/**
 * monitoring.ts — live reliability metrics, computed locally.
 *
 * A faithful port of the Python MonitorSession, including the decisions that
 * were only learned by getting them wrong there. Those are worth restating
 * rather than silently inheriting, because a reimplementation is exactly where
 * a hard-won correction gets quietly dropped.
 *
 * O(1) PER STEP
 * The Python version originally recomputed every metric by rescanning the
 * whole step history on every step, making a run O(n²): at 50,000 steps that
 * cost two minutes of the agent's own execution time. Running tallies replaced
 * it. This file starts with the tallies — there is no reason to reintroduce a
 * bug in order to fix it again.
 *
 * NOTHING SLOW ON THE AGENT'S PATH
 * recordStep does arithmetic and an array push. Every network call happens on
 * a timer, off the caller's await chain. An instrument that adds latency to the
 * system it measures has changed that system.
 *
 * UNDEFINED IS NOT ZERO
 * IRS before any fault, CSI within a single session: these are null, and null
 * survives all the way to the wire. Reporting them as 0 would claim a measured
 * failure on a dimension nothing examined.
 */
import { encrypt, buildHeaders } from './crypto.js'

export interface Thresholds {
  pei?: number
  frr?: number
  irs?: number
  ti?: number
  csi?: number
}

/** Matches DEFAULT_THRESHOLDS in the Python SDK. */
export const DEFAULT_THRESHOLDS: Required<Omit<Thresholds, 'csi'>> = {
  pei: 0.7,
  frr: 0.65,
  irs: 0.6,
  ti: 3.0,
}

export interface HaltPolicy {
  metric: 'pei' | 'frr' | 'irs' | 'ti' | 'csi'
  below: number
  /** Consecutive steps under the floor before halting. Sustained, not instant. */
  forSteps?: number
}

export interface StepInput {
  action?: string
  success?: boolean
  hadFault?: boolean
  /** null means "not applicable" — there was no fault to recover from. */
  recoveredIntentionally?: boolean | null
  traceable?: boolean
  replanned?: boolean
  metadata?: Record<string, unknown>
}

export interface LiveMetrics {
  pei: number | null
  frr: number | null
  irs: number | null
  ti: number | null
  csi: number | null
}

export interface Breach {
  metric: string
  value: number
  threshold: number
  stepIndex: number
}

export interface HaltRecord {
  metric: string | null
  metricValue: number | null
  threshold: number | null
  consecutiveSteps: number | null
  stepIndex: number
  policy: Record<string, unknown>
  reason: string
  triggerSource: 'policy' | 'haltSignal' | 'manual'
  occurredAt: number
}

export interface MonitorOptions {
  agentId: string
  thresholds?: Thresholds
  onThresholdBreach?: (b: Breach, session: MonitorSession) => void
  haltPolicy?: HaltPolicy
  /** Send the summary when the session closes. */
  sendSummary?: boolean
  /** Stream progress while the agent runs. */
  stream?: boolean
  batchSize?: number
  flushIntervalMs?: number
  sessionMetadata?: Record<string, unknown>
}

/** Bound on retained overhead samples; beyond it, reservoir sampling. */
const MAX_OVERHEAD_SAMPLES = 10_000
/** Bound on retained step records. Metrics come from tallies, not this list. */
const MAX_RETAINED_STEPS = 5_000

const DEFAULT_BATCH_SIZE = 25
const DEFAULT_FLUSH_INTERVAL_MS = 2_000
const DEFAULT_HALT_FOR_STEPS = 3

interface Transport {
  gatewayUrl: string
  apiKey: string
  aesKey: Buffer
  signingSecret: Buffer
  protocolVersion: string
}

export class MonitorSession {
  readonly sessionId: string
  readonly agentId: string
  readonly thresholds: Thresholds
  readonly startedAt: number

  /** Recent steps only — bounded. Truncating changes what can be INSPECTED,
   *  never what is MEASURED, because metrics read the tallies below. */
  readonly steps: StepInput[] = []
  private stepCount = 0

  // Running tallies. See the O(1) note at the top of the file.
  private nReplans = 0
  private nFaulted = 0
  private nFaultedSurvived = 0
  private nRecoveryJudged = 0
  private nRecoveryDeliberate = 0
  private nTraceable = 0

  private metrics: LiveMetrics = { pei: null, frr: null, irs: null, ti: null, csi: null }
  private breaches: Breach[] = []
  private breachRun: Record<string, number> = {}
  private announced = new Set<string>()

  private halted = false
  private haltReasonText: string | null = null
  private haltRecordValue: HaltRecord | null = null

  // Overhead measurement, with exact totals and a bounded sample.
  private overheadSamples: number[] = []
  private overheadCount = 0
  private overheadTotal = 0
  private overheadMax = 0

  private queue: unknown[] = []
  private timer: NodeJS.Timeout | null = null
  private closed = false
  private streamedBatches = 0
  private streamErrors = 0

  constructor(
    private readonly transport: Transport,
    private readonly opts: MonitorOptions,
  ) {
    this.sessionId = globalThis.crypto.randomUUID()
    this.agentId = opts.agentId
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...(opts.thresholds ?? {}) }
    this.startedAt = Date.now() / 1000

    if (opts.stream !== false) {
      const every = opts.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS
      this.timer = setInterval(() => { void this.flush() }, every)
      // Do not hold the process open for the sake of telemetry.
      this.timer.unref?.()
    }
  }

  // ── Recording ─────────────────────────────────────────────────────────────
  recordStep(step: StepInput = {}): void {
    if (this.closed) return

    // Everything from here to the sample at the end is the cost this module
    // imposes on the caller's loop.
    const t0 = performance.now()

    const {
      action = '',
      success = true,
      hadFault = false,
      recoveredIntentionally = null,
      traceable = true,
      replanned = false,
    } = step

    this.steps.push(step)
    if (this.steps.length > MAX_RETAINED_STEPS) this.steps.shift()
    this.stepCount += 1

    if (replanned) this.nReplans += 1
    if (traceable) this.nTraceable += 1
    if (hadFault) {
      this.nFaulted += 1
      if (success) this.nFaultedSurvived += 1
      if (recoveredIntentionally !== null && recoveredIntentionally !== undefined) {
        this.nRecoveryJudged += 1
        if (recoveredIntentionally) this.nRecoveryDeliberate += 1
      }
    }

    this.recompute()
    this.checkThresholds(action)

    this.enqueue({ type: 'step', payload: { action, success, hadFault } })
    this.recordOverhead(performance.now() - t0)
  }

  /**
   * Recompute from tallies. O(1).
   *
   * These are LIVE OPERATIONAL SIGNALS, not a formal HB-Eval verdict — the
   * authoritative five-metric scoring stays server-side, on the full battery.
   * This exists to detect degradation fast enough to act on it.
   */
  private recompute(): void {
    const n = this.stepCount
    if (n === 0) return

    // PEI proxy: repeated re-planning means the plan is not holding.
    this.metrics.pei = Math.max(0, 1 - this.nReplans / n)

    // FRR: of steps where a fault was present, how many still completed.
    // Undefined without an observed fault — resilience cannot be scored
    // against nothing.
    this.metrics.frr = this.nFaulted ? this.nFaultedSurvived / this.nFaulted : null

    // IRS: defined only where a recovery judgement was supplied.
    this.metrics.irs = this.nRecoveryJudged
      ? this.nRecoveryDeliberate / this.nRecoveryJudged
      : null

    this.metrics.ti = Math.round((5 * this.nTraceable / n) * 100) / 100

    // CSI needs repeated runs, not steps within one. Never faked from a single
    // session.
    this.metrics.csi = null
  }

  private checkThresholds(action: string): void {
    for (const [metric, floor] of Object.entries(this.thresholds)) {
      if (floor === undefined) continue
      const value = this.metrics[metric as keyof LiveMetrics]

      if (value === null || value >= floor) {
        // Undefined cannot breach, and recovery resets the run so a later
        // breach must build up again from zero.
        this.breachRun[metric] = 0
        continue
      }

      this.breachRun[metric] = (this.breachRun[metric] ?? 0) + 1
      const breach: Breach = {
        metric, value, threshold: floor, stepIndex: this.stepCount - 1,
      }
      this.breaches.push(breach)

      // The callback is the caller's code. An exception in it must not break
      // the session that was observing them.
      if (this.opts.onThresholdBreach && !this.announced.has(metric)) {
        this.announced.add(metric)
        try { this.opts.onThresholdBreach(breach, this) } catch { /* ignore */ }
      }

      this.evaluateHaltPolicy(metric, value)
    }
  }

  private evaluateHaltPolicy(metric: string, value: number): void {
    const policy = this.opts.haltPolicy
    if (!policy || this.halted || policy.metric !== metric) return
    if (value >= policy.below) return

    const forSteps = policy.forSteps ?? DEFAULT_HALT_FOR_STEPS
    if ((this.breachRun[metric] ?? 0) < forSteps) return

    // Sustained, not instantaneous. One bad step is noise, and a guard that
    // fires on noise gets switched off.
    this.halted = true
    this.haltReasonText =
      `${metric.toUpperCase()} stayed below ${policy.below} for ` +
      `${this.breachRun[metric]} consecutive steps`

    // Decomposed as well as rendered: the sentence is what an operator reads,
    // the fields are what a system queries.
    this.haltRecordValue = {
      metric,
      metricValue: value,
      threshold: policy.below,
      consecutiveSteps: this.breachRun[metric] ?? 0,
      stepIndex: this.stepCount - 1,
      policy: { ...policy },
      reason: this.haltReasonText,
      triggerSource: 'policy',
      occurredAt: Date.now() / 1000,
    }
    this.enqueue({ type: 'halt', payload: this.haltRecordValue, urgent: true })
  }

  /** Cooperative stop. Nothing is killed mid-step. */
  halt(reason = 'halted by caller'): void {
    if (this.halted) return
    this.halted = true
    this.haltReasonText = reason
    this.haltRecordValue = {
      metric: null, metricValue: null, threshold: null,
      consecutiveSteps: null, stepIndex: Math.max(0, this.stepCount - 1),
      policy: {}, reason, triggerSource: 'manual',
      occurredAt: Date.now() / 1000,
    }
  }

  // ── Overhead ──────────────────────────────────────────────────────────────
  private recordOverhead(ms: number): void {
    this.overheadCount += 1
    this.overheadTotal += ms
    if (ms > this.overheadMax) this.overheadMax = ms

    if (this.overheadSamples.length < MAX_OVERHEAD_SAMPLES) {
      this.overheadSamples.push(ms)
      return
    }
    // Reservoir sampling keeps the retained set representative of the WHOLE
    // run. Overhead is not stationary: a run that degrades in its final third
    // would be invisible if only the first N steps were kept.
    const j = Math.floor(Math.random() * this.overheadCount)
    if (j < MAX_OVERHEAD_SAMPLES) this.overheadSamples[j] = ms
  }

  private percentile(sorted: number[], q: number): number {
    if (sorted.length === 0) return 0
    if (sorted.length === 1) return sorted[0]!
    const pos = (sorted.length - 1) * q
    const low = Math.floor(pos)
    const high = Math.min(low + 1, sorted.length - 1)
    return sorted[low]! + (sorted[high]! - sorted[low]!) * (pos - low)
  }

  get overheadStats() {
    if (this.overheadCount === 0) {
      // Nothing measured. Zeros would claim a measurement never taken.
      return {
        samples: 0, p50Ms: null, p95Ms: null, p99Ms: null,
        maxMs: null, totalMs: null, estimated: false,
      }
    }
    const sorted = [...this.overheadSamples].sort((a, b) => a - b)
    const round4 = (x: number) => Math.round(x * 10_000) / 10_000
    return {
      samples: this.overheadCount,
      p50Ms: round4(this.percentile(sorted, 0.5)),
      p95Ms: round4(this.percentile(sorted, 0.95)),
      p99Ms: round4(this.percentile(sorted, 0.99)),
      maxMs: round4(this.overheadMax),
      totalMs: Math.round(this.overheadTotal * 1000) / 1000,
      // Says whether the percentiles are exact or sampled, so a reader never
      // has to guess.
      estimated: this.overheadCount > sorted.length,
    }
  }

  // ── Accessors ─────────────────────────────────────────────────────────────
  get liveMetrics(): LiveMetrics { return { ...this.metrics } }
  get shouldHalt(): boolean { return this.halted }
  get haltReason(): string | null { return this.haltReasonText }
  get haltRecord(): HaltRecord | null {
    return this.haltRecordValue ? { ...this.haltRecordValue } : null
  }
  get breachCount(): number { return this.breaches.length }

  get summary() {
    return {
      session_id: this.sessionId,
      agent_id: this.agentId,
      started_at: this.startedAt,
      ended_at: Date.now() / 1000,
      duration_seconds: Math.round(Date.now() / 1000 - this.startedAt),
      step_count: this.stepCount,
      breach_count: this.breaches.length,
      halted: this.halted,
      halt_reason: this.haltReasonText,
      halt_policy: this.opts.haltPolicy ?? null,
      halt_record: this.haltRecord,
      live_metrics: this.liveMetrics,
      thresholds: this.thresholds,
      breaches: this.breaches,
      metadata: { ...(this.opts.sessionMetadata ?? {}), source: 'typescript' },
      overhead: this.overheadStats,
      streaming: {
        batches_sent: this.streamedBatches,
        errors: this.streamErrors,
      },
    }
  }

  // ── Transport ─────────────────────────────────────────────────────────────
  private enqueue(item: unknown): void {
    if (this.opts.stream === false) return
    this.queue.push(item)
    const max = this.opts.batchSize ?? DEFAULT_BATCH_SIZE
    if (this.queue.length >= max) void this.flush()
  }

  private async flush(): Promise<void> {
    if (this.queue.length === 0 || this.opts.stream === false) return
    this.queue = []   // cleared first, so a slow POST cannot double-send

    const batch = {
      session_id: this.sessionId,
      agent_id: this.agentId,
      status: this.halted ? 'halted' : 'active',
      started_at: this.startedAt,
      step_count: this.stepCount,
      breach_count: this.breaches.length,
      halted: this.halted,
      halt_reason: this.haltReasonText,
      live_metrics: this.metrics,
    }

    try {
      await this.post('/api/v1/monitoring/stream', batch)
      this.streamedBatches += 1
    } catch {
      // Fail-soft, always. A telemetry failure must never surface as an agent
      // failure — this module is not permitted to be the reason a run breaks.
      this.streamErrors += 1
    }
  }

  private async post(path: string, payload: unknown): Promise<void> {
    const { nonceHex, ciphertextHex } = encrypt(payload, this.transport.aesKey)
    const timestamp = String(Math.floor(Date.now() / 1000))
    const headers = buildHeaders(
      this.transport.apiKey, this.transport.signingSecret,
      nonceHex, timestamp, ciphertextHex, this.transport.protocolVersion,
    )
    const res = await fetch(`${this.transport.gatewayUrl}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ ciphertext: ciphertextHex }),
      signal: AbortSignal.timeout(10_000),
    })
    if (!res.ok) throw new Error(`Gateway returned ${res.status}`)
  }

  /** Close the session and send the summary. Idempotent. */
  async close(): Promise<void> {
    if (this.closed) return
    this.closed = true
    if (this.timer) { clearInterval(this.timer); this.timer = null }

    await this.flush()
    if (this.opts.sendSummary === false) return
    try {
      await this.post('/api/v1/monitoring/session', this.summary)
    } catch {
      // Same contract as flush: the run already happened, and the metrics are
      // in hand. Losing the upload is not worth raising into the caller.
    }
  }
}
