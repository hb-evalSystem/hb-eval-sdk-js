/**
 * index.ts — the TypeScript SDK for HB-Eval.
 *
 * WHY THIS EXISTS
 * A large share of the agent ecosystem is JavaScript — LangChain.js above all —
 * and until now none of it could reach this platform. The Python semantics have
 * been through eight rounds of correction, which is why this port comes now
 * rather than earlier: maintaining two immature SDKs would have meant fixing
 * every mistake twice.
 *
 *     import { HBEvalClient } from '@hbeval/sdk'
 *
 *     const client = new HBEvalClient({ apiKey, aesKey, signingSecret })
 *
 *     const session = client.monitor({ agentId: 'support-agent' })
 *     try {
 *       for (const step of await agent.run(task)) {
 *         session.recordStep({
 *           action: step.name,
 *           success: step.ok,
 *           hadFault: step.faulted,
 *         })
 *         if (session.shouldHalt) break
 *       }
 *     } finally {
 *       await session.close()
 *     }
 *
 * SCOPE, STATED HONESTLY
 * This first release covers the protocol and live monitoring — the parts a
 * JavaScript agent needs to be measured at all. The fault-injection battery,
 * the policy engine and OpenTelemetry bridging remain Python-only for now.
 * Shipping a thin, correct client beats shipping a broad one whose crypto has
 * not been proven against the Gateway.
 */
export {
  MonitorSession,
  DEFAULT_THRESHOLDS,
  type Thresholds,
  type HaltPolicy,
  type StepInput,
  type LiveMetrics,
  type Breach,
  type HaltRecord,
  type MonitorOptions,
} from './monitoring.js'

export {
  encrypt,
  computeSignature,
  buildHeaders,
  decodeKey,
  generateNonce,
  generateTimestamp,
  safeEqual,
} from './crypto.js'

import { decodeKey, encrypt, buildHeaders } from './crypto.js'
import { MonitorSession, type MonitorOptions } from './monitoring.js'

export const PROTOCOL_VERSION = '2.7.0'
export const VERSION = '0.1.0'

const DEFAULT_GATEWAY =
  'https://hbeval-reliability-os-production.up.railway.app'

export interface ClientOptions {
  apiKey: string
  /** Base64, decoding to exactly 32 bytes. */
  aesKey: string
  /** Base64 or raw text; the separate signing secret, never the API key. */
  signingSecret: string
  gatewayUrl?: string
  timeoutMs?: number
  maxRetries?: number
}

export interface EvaluationPayload {
  trajectory?: Array<Record<string, unknown>>
  sub_tasks?: number
  constraint_violations?: number
  recovery_episodes?: Array<Record<string, unknown>>
  ti_score?: number | null
  context?: string
  agent_id?: string
  [key: string]: unknown
}

export class HBEvalClient {
  readonly gatewayUrl: string
  private readonly apiKey: string
  private readonly aesKey: Buffer
  private readonly signingSecret: Buffer
  private readonly timeoutMs: number
  private readonly maxRetries: number

  constructor(opts: ClientOptions) {
    if (!opts.apiKey) throw new Error('apiKey is required.')

    this.apiKey = opts.apiKey
    // Validated here, not at first request. A 31-byte key fails inside the
    // cipher with a message that names nothing useful.
    this.aesKey = decodeKey(opts.aesKey, 'aesKey')

    // The signing secret is base64 in the dashboard, but accepting raw text
    // costs nothing and saves a confusing failure for anyone who pasted it
    // from somewhere else.
    const decoded = Buffer.from(opts.signingSecret, 'base64')
    this.signingSecret = decoded.length === 32
      ? decoded
      : Buffer.from(opts.signingSecret, 'utf-8')

    this.gatewayUrl = (opts.gatewayUrl ?? DEFAULT_GATEWAY).replace(/\/+$/, '')
    this.timeoutMs = opts.timeoutMs ?? 30_000
    this.maxRetries = opts.maxRetries ?? 2
  }

  /** Open a monitoring session. Remember to `await session.close()`. */
  monitor(opts: MonitorOptions): MonitorSession {
    return new MonitorSession(
      {
        gatewayUrl: this.gatewayUrl,
        apiKey: this.apiKey,
        aesKey: this.aesKey,
        signingSecret: this.signingSecret,
        protocolVersion: PROTOCOL_VERSION,
      },
      opts,
    )
  }

  /**
   * Convenience wrapper that always closes the session.
   *
   * Provided because a forgotten close means the summary is never sent, and a
   * try/finally is easy to omit under a deadline.
   */
  async withMonitor<T>(
    opts: MonitorOptions,
    fn: (session: MonitorSession) => Promise<T> | T,
  ): Promise<T> {
    const session = this.monitor(opts)
    try {
      return await fn(session)
    } finally {
      await session.close()
    }
  }

  /** Submit a completed run for server-side scoring. */
  async evaluate(payload: EvaluationPayload): Promise<Record<string, unknown>> {
    return this.request('/evaluate', payload)
  }

  /** Reliability trend for an agent, across monitored sessions. */
  async getTrend(agentId: string, limit = 20): Promise<Record<string, unknown>> {
    const url =
      `${this.gatewayUrl}/api/v1/monitoring/trend` +
      `?agent_id=${encodeURIComponent(agentId)}&limit=${limit}`
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${this.apiKey}` },
      signal: AbortSignal.timeout(this.timeoutMs),
    })
    if (!res.ok) throw new Error(`Gateway returned ${res.status}`)
    return res.json() as Promise<Record<string, unknown>>
  }

  private async request(
    path: string,
    payload: unknown,
  ): Promise<Record<string, unknown>> {
    let lastError: unknown

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      // Re-encrypted on every attempt, because the nonce must be fresh: the
      // Gateway consumes each one exactly once, so a retry that reuses it is
      // rejected as a replay.
      const { nonceHex, ciphertextHex } = encrypt(payload, this.aesKey)
      const timestamp = String(Math.floor(Date.now() / 1000))
      const headers = buildHeaders(
        this.apiKey, this.signingSecret,
        nonceHex, timestamp, ciphertextHex, PROTOCOL_VERSION,
      )

      try {
        const res = await fetch(`${this.gatewayUrl}${path}`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ ciphertext: ciphertextHex }),
          signal: AbortSignal.timeout(this.timeoutMs),
        })

        if (res.ok) return res.json() as Promise<Record<string, unknown>>

        // 4xx is the caller's problem and will not fix itself; retrying an
        // expired key just delays the error. 5xx and network faults might.
        if (res.status >= 400 && res.status < 500) {
          const detail = await res.text().catch(() => '')
          throw new Error(
            `Gateway rejected the request (${res.status})` +
            (detail ? `: ${detail.slice(0, 200)}` : ''),
          )
        }
        lastError = new Error(`Gateway returned ${res.status}`)
      } catch (err) {
        if (err instanceof Error && err.message.startsWith('Gateway rejected')) {
          throw err
        }
        lastError = err
      }

      if (attempt < this.maxRetries) {
        await new Promise(r => setTimeout(r, 500 * Math.pow(2, attempt)))
      }
    }

    throw lastError instanceof Error
      ? lastError
      : new Error('The request failed.')
  }
}
