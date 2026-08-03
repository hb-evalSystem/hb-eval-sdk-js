/**
 * crypto.ts — the wire protocol, byte for byte.
 *
 * WHY THIS FILE IS THE RISKY ONE
 * Every other part of this SDK can be wrong in a way that produces a bad
 * measurement. This one can be wrong in a way that produces nothing at all:
 * one byte out of place in the ciphertext or the signed message and the
 * Gateway rejects every request, with an error that says only "invalid
 * signature".
 *
 * So it is written against the Python implementation as a specification rather
 * than a reference, and verified by round-trip — encrypt here, decrypt there —
 * instead of by reading both and believing they agree.
 *
 * WHAT DOES NOT NEED TO MATCH, AND WHY
 * Python's json.dumps emits `{"a": 1}` with spaces and escapes non-ASCII;
 * JSON.stringify emits `{"a":1}` and does not. The plaintext bytes therefore
 * differ, and so does the ciphertext.
 *
 * That is fine, and worth stating plainly because it looks alarming at first.
 * The Gateway decrypts and parses; whitespace and escaping are invisible to
 * json.loads. What must match is the SIGNATURE ALGORITHM over whatever
 * ciphertext this client actually produced — the signature covers this
 * client's own bytes, not a canonical form of them.
 *
 * ZERO DEPENDENCIES
 * node:crypto only. Installing an SDK to measure an agent's reliability should
 * not drag a supply chain into that agent's environment — the same principle
 * that keeps the Python core to the standard library.
 */
import { createCipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

/** Protocol §3: AES-256-GCM with a 12-byte nonce. */
export const NONCE_BYTES = 12
export const KEY_BYTES = 32

/**
 * Decode a base64 key and check its length.
 *
 * Checked at construction rather than at first request: a 31-byte key fails
 * inside the cipher with a message that says nothing about which key was
 * wrong, and finding that out at 3am is worse than finding it out at startup.
 */
export function decodeKey(b64: string, label: string): Buffer {
  let key: Buffer
  try {
    key = Buffer.from(b64, 'base64')
  } catch {
    throw new Error(`${label} is not valid base64.`)
  }
  if (key.length !== KEY_BYTES) {
    throw new Error(
      `${label} must decode to ${KEY_BYTES} bytes, got ${key.length}. ` +
      `Copy it exactly as shown when the agent was created.`,
    )
  }
  return key
}

/** Protocol §3: 12 random bytes, transported as 24 hex characters. */
export function generateNonce(): { bytes: Buffer; hex: string } {
  const bytes = randomBytes(NONCE_BYTES)
  return { bytes, hex: bytes.toString('hex') }
}

/** Protocol §3: whole Unix seconds, as a string. */
export function generateTimestamp(): string {
  return String(Math.floor(Date.now() / 1000))
}

/**
 * Encrypt a payload with AES-256-GCM.
 *
 * The authentication tag is appended to the ciphertext, which is what Python's
 * AESGCM.encrypt returns and therefore what the Gateway expects to slice off
 * the end. Returning them separately would decrypt to garbage.
 */
export function encrypt(
  payload: unknown,
  aesKey: Buffer,
): { nonceHex: string; ciphertextHex: string } {
  const { bytes: nonce, hex: nonceHex } = generateNonce()
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf-8')

  const cipher = createCipheriv('aes-256-gcm', aesKey, nonce)
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()

  // Tag last. This ordering is the protocol, not a convention.
  return {
    nonceHex,
    ciphertextHex: Buffer.concat([encrypted, tag]).toString('hex'),
  }
}

/**
 * Protocol §4: HMAC-SHA256 over `nonceHex.timestamp.ciphertextHex`.
 *
 * Keyed with the SEPARATE signing secret — never the API key, never a hash of
 * it. The ciphertext sits inside the signed message so that tampering with the
 * encrypted payload invalidates the signature rather than merely corrupting
 * the plaintext.
 */
export function computeSignature(
  signingSecret: Buffer,
  nonceHex: string,
  timestamp: string,
  ciphertextHex: string,
): string {
  const message = `${nonceHex}.${timestamp}.${ciphertextHex}`
  return createHmac('sha256', signingSecret).update(message, 'utf-8').digest('hex')
}

/**
 * Constant-time comparison, for anything that verifies a signature locally.
 *
 * Unused on the request path — this client signs, it does not verify — but
 * present so a future webhook-receiver helper cannot be written with `===` by
 * someone who did not know to reach for this.
 */
export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf-8')
  const bb = Buffer.from(b, 'utf-8')
  if (ba.length !== bb.length) return false
  return timingSafeEqual(ba, bb)
}

/** Protocol §4: the headers every authenticated request carries. */
export function buildHeaders(
  apiKey: string,
  signingSecret: Buffer,
  nonceHex: string,
  timestamp: string,
  ciphertextHex: string,
  protocolVersion: string,
): Record<string, string> {
  return {
    'Authorization': `Bearer ${apiKey}`,
    'X-HBEval-Nonce': nonceHex,
    'X-HBEval-Timestamp': timestamp,
    'X-HBEval-Signature': computeSignature(
      signingSecret, nonceHex, timestamp, ciphertextHex,
    ),
    'X-HBEval-Protocol': protocolVersion,
    'Content-Type': 'application/json',
  }
}
