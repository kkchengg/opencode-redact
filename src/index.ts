/**
 * @kkcheng/opencode-redact
 *
 * Two-way secret redaction for OpenCode v2.
 *
 * Outbound (protected): API keys, tokens, passwords and other secrets are
 * replaced with stable placeholders like `[REDACTED:aws-access-key:0000a1b2c3d4]`
 * before anything is sent to the model.
 *
 * Inbound (rehydrated): just before a tool runs, placeholders in the tool input
 * are swapped back to the real secret, so commands that need the value still
 * work. The model itself never sees the real secret.
 *
 * The plugin is intentionally dependency-free and self-contained: it exports a
 * plain `{ id, setup }` object, which is exactly what the OpenCode v2 loader
 * accepts. It does not need `@opencode/plugin` at runtime.
 *
 * Notes / limits:
 * - The vault lives in this process. If the OpenCode service restarts mid
 *   session, placeholders already in history can no longer be rehydrated.
 * - Redaction is applied to the outgoing request only; persisted local history
 *   and unrelated configuration are not modified.
 */

interface Rule {
  name: string
  re: RegExp
  /** 1-based capture group holding the secret; defaults to the whole match. */
  group?: number
}

const RULES: Rule[] = [
  // Cloud
  { name: "aws-access-key", re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  { name: "gcp-api-key", re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  // Code hosting
  { name: "github-pat", re: /\bgh[pousr]_[A-Za-z0-9]{20,255}\b/g },
  { name: "github-fine-grained", re: /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g },
  { name: "gitlab-pat", re: /\bglpat-[A-Za-z0-9_\-]{20,}\b/g },
  // Model providers
  { name: "openai-key", re: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b/g },
  { name: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g },
  // Other services
  { name: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: "stripe-key", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { name: "npm-token", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { name: "pypi-token", re: /\bpypi-[A-Za-z0-9_\-]{50,}\b/g },
  // Structured secrets
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  {
    name: "private-key",
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  // Generic `password = "..."` / `api_key: ...` assignments (value only).
  {
    name: "credential",
    re: /(\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*)(["']?)([^\s"',;]{6,})/gi,
    group: 3,
  },
]

// ---------------------------------------------------------------------------
// Vault: placeholder token -> original secret
// ---------------------------------------------------------------------------

const MAX_VAULT = 4096
const vault = new Map<string, string>()

/** Stable, short, non-cryptographic fingerprint so a secret maps to one token. */
function fingerprint(secret: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < secret.length; i++) {
    h ^= secret.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(16).padStart(12, "0")
}

function remember(rule: string, secret: string): string {
  const token = `[REDACTED:${rule}:${fingerprint(secret)}]`
  if (!vault.has(token)) {
    if (vault.size >= MAX_VAULT) {
      const oldest = vault.keys().next().value
      if (oldest !== undefined) vault.delete(oldest)
    }
    vault.set(token, secret)
  }
  return token
}

const TOKEN_RE = /\[REDACTED:[a-z0-9-]+:[0-9a-f]{12}\]/g

/**
 * Replace secrets with tokens. Every rule scans the original text, so no rule
 * can match inside another rule's token. Ranges already covered by a token
 * (a secret re-sent on a later turn) are reserved so the generic assignment
 * rule cannot match inside `...access-key:<hash>]`.`.
 */
function redactString(text: string): string {
  if (!text) return text

  const reserved: Array<[number, number]> = []
  TOKEN_RE.lastIndex = 0
  for (const match of text.matchAll(TOKEN_RE)) {
    const start = match.index ?? 0
    reserved.push([start, start + match[0].length])
  }
  const overlaps = (start: number, end: number) => reserved.some(([a, b]) => start < b && end > a)

  const edits: Array<{ start: number; end: number; token: string }> = []
  for (const rule of RULES) {
    rule.re.lastIndex = 0
    for (const match of text.matchAll(rule.re)) {
      const whole = match[0]
      const base = match.index ?? 0
      const secret = rule.group ? match[rule.group] : whole
      if (typeof secret !== "string" || secret.length === 0) continue
      const at = rule.group ? whole.indexOf(secret) : 0
      if (at < 0) continue
      const start = base + at
      const end = start + secret.length
      if (overlaps(start, end)) continue
      reserved.push([start, end])
      edits.push({ start, end, token: remember(rule.name, secret) })
    }
  }

  if (edits.length === 0) return text
  edits.sort((a, b) => a.start - b.start)
  let out = ""
  let cursor = 0
  for (const edit of edits) {
    out += text.slice(cursor, edit.start) + edit.token
    cursor = edit.end
  }
  return out + text.slice(cursor)
}

function rehydrateString(text: string): string {
  if (!text.includes("[REDACTED:")) return text
  return text.replace(TOKEN_RE, (token) => vault.get(token) ?? token)
}

// ---------------------------------------------------------------------------
// Deep string walking (mutates in place)
// ---------------------------------------------------------------------------

const MAX_STRING = 200_000

/** Skip large binary-ish blobs (base64, image data) so we never corrupt them. */
function isOpaque(value: string): boolean {
  if (value.length > MAX_STRING) return true
  if (value.startsWith("data:")) return true
  if (value.length > 4096 && !value.includes(" ") && /^[A-Za-z0-9+/=\s]+$/.test(value)) return true
  return false
}

function walkStrings(
  value: unknown,
  fn: (s: string) => string,
  skipOpaque: boolean,
  seen = new WeakSet<object>(),
  depth = 0,
): void {
  if (depth > 16 || value === null || typeof value !== "object") return
  if (seen.has(value)) return
  seen.add(value)

  const apply = (input: string): string | undefined => {
    if (skipOpaque && isOpaque(input)) return undefined
    const next = fn(input)
    return next === input ? undefined : next
  }

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const item = value[i]
      if (typeof item === "string") {
        const next = apply(item)
        if (next !== undefined) {
          try {
            value[i] = next
          } catch {
            // Frozen or read-only entry: leave it untouched.
          }
        }
      } else {
        walkStrings(item, fn, skipOpaque, seen, depth + 1)
      }
    }
    return
  }

  for (const key of Object.keys(value as Record<string, unknown>)) {
    const item = (value as Record<string, unknown>)[key]
    if (typeof item === "string") {
      const next = apply(item)
      if (next !== undefined) {
        try {
          ;(value as Record<string, unknown>)[key] = next
        } catch {
          // Frozen or read-only field: leave it untouched.
        }
      }
    } else {
      walkStrings(item, fn, skipOpaque, seen, depth + 1)
    }
  }
}

function redactValue(value: unknown): unknown {
  if (typeof value === "string") return isOpaque(value) ? value : redactString(value)
  walkStrings(value, redactString, true)
  return value
}

function rehydrateValue(value: unknown): unknown {
  if (typeof value === "string") return rehydrateString(value)
  walkStrings(value, rehydrateString, false)
  return value
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default {
  id: "opencode-redact",
  async setup(ctx: any) {
    // 1. Redact the user's prompt at admission.
    await ctx.session.hook("prompt", (event: any) => {
      if (typeof event.prompt?.text === "string") {
        event.prompt.text = redactValue(event.prompt.text) as string
      }
    })

    // 2. Redact the assembled request (system, messages, tool definitions)
    //    right before it is sent to the model.
    await ctx.session.hook("context", (event: any) => {
      try {
        redactValue(event.system)
        redactValue(event.messages)
        redactValue(event.tools)
      } catch {
        // Redaction must never break a request.
      }
    })

    // 3. Rehydrate placeholders in tool input just before execution, so the
    //    real secret is used locally without ever reaching the model.
    if (ctx.tool && typeof ctx.tool.hook === "function") {
      await ctx.tool.hook("execute.before", (event: any) => {
        try {
          event.input = rehydrateValue(event.input)
        } catch {
          // Rehydration must never break a tool call.
        }
      })
    }
  },
}
