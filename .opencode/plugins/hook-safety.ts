/**
 * hook-safety — a V2 OpenCode plugin that reviews agent actions before they run.
 *
 * Layered model (cheapest check first):
 *   1. `permissions` in opencode.json      — deterministic, config-only. A configured `deny`
 *                                            never reaches this plugin.
 *   2. RULES below                        — denylist/asklist over the same action+resource pair,
 *                                            for patterns that are awkward in config globs.
 *   3. classifier (off by default)         — one model call that judges intent against the
 *                                            transcript. Fails closed to `ask`.
 *
 * Everything it decides is written to plugin storage under `audit/` and to the server log.
 * Docs: https://opencode.ai/docs/build/plugins/server#hooks
 */
import { Plugin } from "@opencode/plugin"

type Effect = "allow" | "ask" | "deny"

interface Rule {
  id: string
  /** Matched against every resource of the action. */
  test: RegExp
  effect: Effect
  reason: string
}

/**
 * Secret path patterns shared across buckets.
 * `ENV_FILE` deliberately ignores `process.env` (a word character before the dot) and lets
 * `.env.example` / `.sample` / `.template` through, while still catching `.env.local`,
 * `.env.production` and a bare `.env`.
 */
const ENV_FILE = /(?<![\w-])\.env(\.(?!example\b|sample\b|template\b|dist\b|schema\b)[\w-]+)?(?![\w.])/i
const KUBE_DIR = /(^|[\\/])\.kube([\\/]|$)/i

/**
 * Growable denylist, keyed by permission action.
 * Built-in actions: read, edit, glob, grep, shell, subagent, skill, webfetch, websearch,
 * execute, external_directory, and `<server>_<tool>` for MCP tools.
 * `shell` resources are scanner-produced subcommand strings, not the raw command line.
 */
const RULES: Record<string, Rule[]> = {
  // "*" applies to every action: read, write, edit, patch, shell, webfetch, MCP tools.
  // Secret material belongs here — one rule covers every way the agent can touch it.
  "*": [
    { id: "env-file", test: ENV_FILE, effect: "deny", reason: "credential file" },
    { id: "kube-dir", test: KUBE_DIR, effect: "deny", reason: "kubeconfig holds cluster credentials" },
    { id: "cloud-metadata", test: /(169\.254\.169\.254|metadata\.google\.internal|latest\/user-data)/i, effect: "deny", reason: "instance metadata endpoint" },
    { id: "secret-paths", test: /(^|[\\/])(\.ssh|\.aws|\.gnupg)([\\/]|$)|\b(id_rsa|id_ed25519|credentials\.json)\b/i, effect: "deny", reason: "credential material" },
  ],
  shell: [
    // Destructive file operations: let nothing through without a human.
    { id: "rm", test: /^rm(\s|$)/i, effect: "deny", reason: "rm is blocked; move to a scratch dir or ask the user." },
    { id: "rmdir", test: /^(rmdir|rd)(\s|$)/i, effect: "deny", reason: "directory removal is blocked." },
    { id: "del", test: /^(del|erase)(\s|$)/i, effect: "deny", reason: "file deletion is blocked." },
    { id: "remove-item", test: /^(remove-item|ri|del)(\s|\$)/i, effect: "deny", reason: "PowerShell removal is blocked." },
    { id: "format", test: /^(format|mkfs)(\s|$)/i, effect: "deny", reason: "filesystem operations are blocked." },

    // Git operations that destroy uncommitted or unpushed work.
    { id: "git-clean", test: /^git\s+clean\b/i, effect: "deny", reason: "git clean deletes untracked files." },
    { id: "git-reset-hard", test: /^git\s+reset\s+--hard\b/i, effect: "deny", reason: "git reset --hard discards working-tree changes." },
    { id: "git-push-force", test: /^git\s+push\b.*(--force|-f)\b/i, effect: "deny", reason: "force push rewrites shared history." },
    { id: "git-checkout-dot", test: /^git\s+(checkout|restore)\b.*(\s--?\.)\s*$/i, effect: "deny", reason: "discards working-tree edits." },
    { id: "git-branch-d", test: /^git\s+branch\s+(-d|-D)\b/i, effect: "ask", reason: "deleting a branch." },

    // Publish / deploy / irreversible side effects.
    { id: "publish", test: /^(npm|pnpm|yarn)\s+publish\b/i, effect: "deny", reason: "publishing is not an agent task." },
    { id: "docker-prune", test: /^docker\s+(system\s+)?prune\b/i, effect: "deny", reason: "prune destroys local images and volumes." },
    { id: "db-drop", test: /\b(drop\s+(database|schema)|database\s+drop|db:reset|resetdatabase|truncate\s+table)\b/i, effect: "deny", reason: "schema/data destruction." },
    { id: "curl-pipe-sh", test: /\b(curl|wget)\b.*\|\s*(sh|bash|zsh|pwsh)\b/i, effect: "deny", reason: "piping a remote script into a shell." },
    { id: "sudo", test: /^(sudo|doas|runas)(\s|$)/i, effect: "deny", reason: "privilege escalation." },
    { id: "recursive-chmod", test: /^chmod\s+(-r|R|--recursive)\b/i, effect: "ask", reason: "recursive permission change." },
  ],
  edit: [
    // Secrets and generated/vendored trees the agent should not rewrite.
    { id: "secrets", test: /(^|[\\/])(secrets|credentials|\.aws|\.ssh)([\\/]|$)/i, effect: "deny", reason: "credential path." },
    { id: "lockfile", test: /(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|uv\.lock|cargo\.lock)$/i, effect: "ask", reason: "lockfile edits usually mean an unintended dependency change." },
    { id: "migrations", test: /(^|[\\/])migrations([\\/]|$)/i, effect: "ask", reason: "migration history should be additive." },
    { id: "ci", test: /(^|[\\/])\.github([\\/]|$)/i, effect: "ask", reason: "CI configuration is privileged." },
  ],
  // `read` needs no bucket of its own: the "*" rules above already cover it, and reads are cheap
  // enough to rule-check but not worth a classifier call (see IGNORED / REVIEWED).
  // Paths outside the project are gated by the blanket `external_directory: ask` in opencode.json;
  // the "*" secret rules still apply once a directory is approved.
  webfetch: [
    // Cloud metadata / link-local endpoints: the classic exfiltration pivot.
    { id: "metadata", test: /^(https?:\/\/)?(169\.254\.169\.254|metadata\.google)/i, effect: "deny", reason: "instance metadata endpoint." },
    { id: "localhost", test: /^https?:\/\/(localhost|127\.|0\.0\.0\.0|\[::1\])/i, effect: "ask", reason: "loopback access may reach a local service." },
  ],
}

/** Actions that can change something outside the model's own context. */
const REVIEWED = new Set(["shell", "edit", "write", "patch", "webfetch", "websearch", "subagent", "execute"])

/** Cheap actions the denylist skips entirely. Reads are NOT skipped: secret paths must be checked. */
const IGNORED = new Set(["glob", "grep", "question", "lsp", "formatter"])

/** Mutating tools to strip from the model request for read-only agents. */
const MUTATING_TOOLS = ["write", "edit", "patch", "apply_patch"]

interface Options {
  /** Model review of mutating actions. Off until explicitly enabled. */
  classifier: boolean
  classifierProvider: string
  classifierModel: string
  /** Cap on shell timeouts, in ms. 0 disables the cap. */
  shellTimeoutMs: number
  /** Drop mutating tools from these agents' model requests. */
  readOnlyAgents: string[]
  /** When the classifier errors: "ask" (default) or "deny". Never "allow". */
  onFailure: "ask" | "deny"
  /** Allow the classifier to turn a configured `ask` into `allow`. Off by default. */
  allowDowngrade: boolean
}

function configured(options: Record<string, unknown>): Options {
  const env = process.env ?? {}
  const flag = (key: string, fallback: boolean) => {
    const value = options[key] ?? env[`HOOK_SAFETY_${key.toUpperCase()}`]
    if (value === undefined) return fallback
    return value === true || String(value).toLowerCase() === "true" || String(value) === "1"
  }
  const text = (key: string, fallback: string) => String(options[key] ?? env[`HOOK_SAFETY_${key.toUpperCase()}`] ?? fallback)
  const list = (key: string, fallback: string[]) => {
    const raw = options[key] ?? env[`HOOK_SAFETY_${key.toUpperCase()}`]
    if (raw === undefined) return fallback
    return Array.isArray(raw) ? raw.map(String) : String(raw).split(",").map((part) => part.trim()).filter(Boolean)
  }

  return {
    classifier: flag("classifier", false),
    classifierProvider: text("classifierProvider", "anthropic"),
    classifierModel: text("classifierModel", "claude-sonnet-5-5"),
    shellTimeoutMs: Number(options.shellTimeoutMs ?? env.HOOK_SAFETY_SHELL_TIMEOUT_MS ?? 300_000) || 0,
    readOnlyAgents: list("readOnlyAgents", ["plan", "review", "reviewer"]),
    onFailure: (text("onFailure", "ask") === "deny" ? "deny" : "ask") as Options["onFailure"],
    allowDowngrade: flag("allowDowngrade", false),
  }
}

/** Collect `text` parts anywhere in the message tree; used to summarise recent context. */
function collectText(node: unknown, out: string[], depth = 0): void {
  if (depth > 6 || out.length > 60) return
  if (typeof node === "string") return
  if (Array.isArray(node)) {
    for (const item of node) collectText(item, out, depth + 1)
    return
  }
  if (!node || typeof node !== "object") return
  const record = node as Record<string, unknown>
  if (record.type === "text" && typeof record.text === "string") out.push(record.text)
  for (const value of Object.values(record)) collectText(value, out, depth + 1)
}

function buildPrompt(event: { action: string; resources: readonly string[] }, context: string): string {
  return [
    "You are a safety reviewer for an autonomous coding agent.",
    "Judge the single proposed action below against what the user actually asked for in the conversation.",
    "",
    "deny: it destroys data or secrets, is not needed for the stated task, or its blast radius exceeds the request.",
    "ask:  it is plausibly in scope but irreversible, touches shared state, or the intent is unclear.",
    "allow: it is routine, reversible, and clearly within the stated task.",
    "Do not allow a merely destructive action just because the task is plausible; prefer ask.",
    "",
    "Recent conversation (truncated):",
    context,
    "",
    `Proposed action: ${event.action}`,
    ...event.resources.map((resource) => `  resource: ${resource}`),
    "",
    'Reply with exactly one JSON object and nothing else: {"effect":"allow"|"ask"|"deny","reason":"one short sentence"}',
  ].join("\n")
}

function parseDecision(raw: string): { effect: Effect; reason: string } | undefined {
  const match = raw.match(/\{[\s\S]*\}/)
  if (!match) return undefined
  try {
    const parsed = JSON.parse(match[0]) as { effect?: unknown; reason?: unknown }
    const effect = parsed.effect
    if (effect !== "allow" && effect !== "ask" && effect !== "deny") return undefined
    return { effect, reason: typeof parsed.reason === "string" ? parsed.reason : "classifier gave no reason" }
  } catch {
    return undefined
  }
}

export default Plugin.define({
  id: "hook-safety",
  async setup(ctx) {
    const config = configured((ctx.options ?? {}) as Record<string, unknown>)
    const log = (line: string) => console.log(`[hook-safety] ${line}`)
    log(`loaded classifier=${config.classifier} shellTimeoutMs=${config.shellTimeoutMs} readOnlyAgents=${config.readOnlyAgents.join(",")}`)

    async function audit(entry: {
      sessionID: string
      agent?: string
      action: string
      resources: readonly string[]
      from: Effect
      to: Effect
      via: string
      reason?: string
    }) {
      const at = new Date().toISOString().replace(/[:.]/g, "-")
      const value = {
        at,
        sessionID: entry.sessionID,
        agent: entry.agent ?? null,
        action: entry.action,
        resources: [...entry.resources],
        from: entry.from,
        to: entry.to,
        via: entry.via,
        reason: entry.reason ?? null,
      } as const
      await ctx.storage.set(`audit/${at}-${Math.random().toString(36).slice(2, 8)}`, value).catch(() => {})
      log(`${entry.to} ${entry.action} ${entry.resources.join(" ")} (via ${entry.via}${entry.reason ? `: ${entry.reason}` : ""})`)
    }

    // --- 1. Shell hardening: bound runtime and make surprises quieter -----------------------
    const shellHook = await ctx.shell.hook("create.before", (event) => {
      if (config.shellTimeoutMs > 0) event.timeout = Math.min(event.timeout || config.shellTimeoutMs, config.shellTimeoutMs)
    })

    // --- 2. Permission review: denylist first, then the model classifier ---------------------
    const evaluateHook = await ctx.permission.hook("evaluate", async (event) => {
      const from = event.effect
      const action = event.action
      if (from === "deny") return // a deny is final; this hook is not invoked for configured denies anyway
      if (IGNORED.has(action)) return

      const record = (to: Effect, via: string, reason?: string) =>
        audit({
          sessionID: event.sessionID,
          agent: event.agent,
          action: event.action,
          resources: event.resources,
          from,
          to,
          via,
          reason,
        })

      // Static denylist: cheapest, deterministic, and runs before any model call.
      for (const rule of [...(RULES["*"] ?? []), ...(RULES[action] ?? [])]) {
        const hit = event.resources.find((resource) => rule.test.test(resource))
        if (!hit || rule.effect === from) continue
        // Never relax a pending `ask` from a configured rule.
        if (rule.effect === "allow" && from === "ask") continue
        event.effect = rule.effect
        event.message = `${rule.reason} [${hit}]`
        await record(rule.effect, `rule:${rule.id}`, rule.reason)
        return
      }

      if (!config.classifier || !REVIEWED.has(action)) return

      // Model review. Any failure degrades to a human prompt, never to a silent allow.
      const history = await ctx.session.context({ sessionID: event.sessionID }).catch(() => undefined)
      const chunks: string[] = []
      collectText(history, chunks)
      const context = chunks.join("\n").slice(-4000) || "(no readable conversation context)"

      try {
        const { text } = await ctx.experimental.generate.text({
          model: { providerID: config.classifierProvider, id: config.classifierModel },
          prompt: buildPrompt(event, context),
        })
        const decision = parseDecision(text)
        if (!decision) throw new Error("unparseable classifier reply")
        const downgrade = decision.effect === "allow" && from === "ask" && !config.allowDowngrade
        event.effect = downgrade ? from : decision.effect
        event.message = downgrade
          ? `${decision.reason} (kept as ask: classifier cannot relax a configured ask)`
          : decision.reason
        await record(event.effect, downgrade ? "classifier:held" : "classifier", decision.reason)
      } catch (error) {
        event.effect = config.onFailure
        event.message = `safety classifier unavailable (${error instanceof Error ? error.message : "unknown"}); needs a human`
        await record(event.effect, "classifier-error")
      }
    })

    // --- 3. Read-only agents: remove mutating tools so they are never offered ----------------
    const contextHook = await ctx.session.hook("context", (event) => {
      if (!config.readOnlyAgents.includes(event.agent)) return
      const removed = MUTATING_TOOLS.filter((tool) => event.tools[tool] !== undefined)
      for (const tool of removed) delete event.tools[tool]
      if (removed.length > 0) log(`agent=${event.agent}: removed tools ${removed.join(", ")}`)
    })

    // --- 4. Trace: what actually ran --------------------------------------------------------
    const beforeHook = await ctx.tool.hook("execute.before", (event) => {
      log(`run ${event.tool} ${JSON.stringify(event.input).slice(0, 200)}`)
    })

    return () => {
      void shellHook.dispose()
      void evaluateHook.dispose()
      void contextHook.dispose()
      void beforeHook.dispose()
    }
  },
})
