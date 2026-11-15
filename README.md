# hook-safety (opencode-hook-safety)

An [OpenCode](https://opencode.ai) V2 plugin that reviews agent tool calls **before they run**:
it blocks credential reads, destructive shell commands, and exfiltration-shaped URLs, and can
optionally put a second model in the loop to judge intent. Ships with the `permissions` config
block it is designed to sit behind.

> **Scope first.** This is a gate on agent actions that pass through OpenCode's permission layer.
> It is not a sandbox — see [What this does NOT protect against](#what-this-does-not-protect-against).
>
> **Written with AI.** See [About this code](#about-this-code) before trusting the rule set.

## Install

Requires OpenCode ≥ 2.2 (V2 plugin API) and Node ≥ 24 (the plugin ships as TypeScript; OpenCode
loads it directly, no build step).

```sh
opencode plugin add opencode-hook-safety
```

Or declare it in `opencode.json(c)` — global for every project, or per project:

```jsonc
{
  "plugins": [
    {
      "package": "opencode-hook-safety",
      "options": {
        "classifier": false,
        "shellTimeoutMs": 300000,
        "readOnlyAgents": ["plan", "review", "reviewer"]
      }
    }
  ]
}
```

No npm package yet? Copy `.opencode/plugins/hook-safety.ts` into your project's
`.opencode/plugins/` directory — plugins there load automatically, no `plugins` entry needed.

Then add the [`permissions` block from `.opencode/opencode.jsonc`](.opencode/opencode.jsonc) to
your own config. The plugin is deliberately built to sit behind it: config denies are final and
costless, the plugin only sees what config let through as `allow` or `ask`.

Verify it loaded: start OpenCode in a project using the plugin and try to read any `.env` path —
you should get `permission.rejected`. Decisions appear as `[hook-safety]` lines in the server log
(`~/.local/share/opencode/log/opencode.log`) and under plugin storage keys `audit/*`.

## Options

Every option also reads an environment variable (`HOOK_SAFETY_` + upper-camel-case key, e.g.
`HOOK_SAFETY_CLASSIFIERPROVIDER`). Options win over env.

| Option | Default | Effect |
| --- | --- | --- |
| `classifier` | `false` | Enable the model-based intent review for mutating actions. Costs one model call per reviewed action. |
| `classifierProvider` | `anthropic` | Provider for the classifier call. |
| `classifierModel` | `claude-sonnet-5-5` | Model for the classifier call. Set both to something you have credentials for. |
| `shellTimeoutMs` | `300000` | Cap on shell command timeouts. `0` disables the cap. |
| `readOnlyAgents` | `plan,review,reviewer` | Agents whose model requests have mutating tools (`write`, `edit`, `patch`, `apply_patch`) stripped. |
| `onFailure` | `ask` | What happens when the classifier errors or replies unparseably: `ask` or `deny`. Never `allow`. |
| `allowDowngrade` | `false` | Allow the classifier to turn a configured `ask` into `allow`. Off by default, on purpose. |

## Behaviour

```
tool call → permissions rules (last match wins) → saved approvals → policies
          → permission.hook("evaluate")  ← this plugin
          → prompt, if still `ask`
```

1. **Secret paths (`"*"` bucket)** — denied for *every* action: `.env` and variants, `.kube/`,
   `.ssh/`, `.aws/`, `.gnupg/`, `id_rsa`, `credentials.json`, cloud metadata endpoints.
   `.env.example|sample|template|dist|schema` are intentionally allowed; `process.env` in a
   command does not match.
2. **Action rules** — denylist/asklist per action: `rm`, `del`, `Remove-Item`, `mkfs`,
   `git clean`/`reset --hard`/`push --force`, `npm publish`, `docker prune`, `DROP DATABASE`,
   `curl | bash`, `sudo`, recursive `chmod`, lockfile and migration and `.github` edits,
   loopback `webfetch`, …
3. **Classifier (off by default)** — one stateless model call judging the action against the
   conversation transcript. Fails closed to `ask`. It never relaxes a configured `ask` unless
   `allowDowngrade` is set.
4. **Side rails** — shell timeout cap, mutating tools stripped from read-only agents, every tool
   execution logged, every decision audited.

Audit records (JSON, one per decision, under `audit/<timestamp>-<id>` in plugin storage) carry
`from`, `to`, `via` (`rule:<id>` | `classifier` | `classifier-error`) and the reason, so you can
answer "who stopped that command" after the fact.

## Growing the rules

Edit `RULES` in `.opencode/plugins/hook-safety.ts`. Key by permission action (`shell`, `edit`,
`webfetch`, `subagent`, `execute`, `"*"` for everything, or `<server>_<tool>` for MCP tools):

```ts
shell: [
  { id: "kubernetes", test: /^kubectl\s+(delete|drain|cordon)\b/i, effect: "deny", reason: "cluster mutation." },
]
```

Notes that matter in practice:

- `shell` resources are **scanner-produced subcommand strings**, not your raw command line; a
  compound command yields several resources and any `deny` blocks the whole thing.
- In config globs, a pattern ending in ` *` also matches the bare command, and `*.env` matches a
  path tail (`/repo/deploy/.env`). `$HOME` is expanded before matching.
- Paths arrive normalised with `/` and match case-insensitively on Windows.
- `external_directory` is **allowed by default** upstream; setting it to `ask` with explicit
  allows (see the example config) is the single highest-value rule you can add.

## Development

```sh
npm ci
npm run check   # tsc against the real @opencode/plugin types + 12 behavioural tests
```

The tests drive the hooks with a stub plugin context — no OpenCode instance or model access
needed. The dogfood layout: this repo's own config loads its own plugin, and the CI workflow runs
`npm run check` on Linux and Windows.

## What this does NOT protect against

This gates **agent tool calls that pass through OpenCode's permission layer**, in the same trust
domain as the agent. It cannot see:

- what a program the agent launched actually does (`python migrate.py --force` is one opaque
  resource; the `rm` inside that script is invisible here),
- processes started outside OpenCode, or another agent framework pointed at your machine,
- network egress, ambient credentials in environment variables, or anything reachable from the
  host user account,
- a semantically wrong but permitted action — the denylist is pattern-based; only the optional
  classifier reasons about intent, and it is advisory.

For that class of risk you need a boundary **under** the agent: something that enforces filesystem
and network access independently of OpenCode, with the agent's credentials kept out of reach.
Keep git history as the recovery layer either way. Rules like these reduce the blast radius of
day-to-day agent mistakes; they are not a security boundary against a determined adversary.

## About this code

Almost all of it was written by an AI coding agent running in OpenCode, in a single working
session, including the test suite and this README. A human directed the work, reviewed the diffs,
and ran the verification described above against a live OpenCode instance.

Read that as: the behaviour claims are tested, but the rule set is a starting point distilled from
one person's threat model, not a reviewed security policy. Read `RULES` before you rely on it, and
send corrections.

## License

Apache-2.0 — see [LICENSE](LICENSE).
