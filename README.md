# site-recon

**Browse a website. Get its API documented.**

`site-recon` is a [Claude Code](https://claude.com/claude-code) skill that turns a
real, human-driven browsing session into **official-style API documentation** —
every endpoint, how to call it, what it returns, the auth flow, and the defenses.
You drive a real browser and log in yourself; the skill only *watches* the
network traffic and the page's JavaScript, then writes the docs.

No bots. No replayed requests. Pure passive observation + static analysis.

---

## Why

Mapping a site's backend by hand means opening DevTools, copying requests one by
one, guessing at parameters, and piecing together the flow. `site-recon` does
that for you: you navigate normally, say "done", and it produces a single
document that explains how the whole site works — like a Swagger you can read.

## What you get

- **Readable API docs** (`API_DOCUMENTATION.md`): transport, auth flow, every
  endpoint with parameter tables and response schemas, the end-to-end flow, and
  a gaps list.
- **Importable specs**: `openapi.json` (Swagger UI / Insomnia), a Postman
  collection, and a `.http` file — your token kept out as `{{token}}`.
- **Inferred schemas**: field types merged across samples; repeated short values
  become enums (e.g. `idstatus: L|R|O|B`).
- **Static↔runtime correlation**: each captured call mapped to the `file:line`
  in the bundle that builds it (optionally via the `reverse-engineer-anything`
  skill / REA for big or minified bundles).
- **Flow diagram**: a Mermaid sequence rebuilt from request timestamps.
- **Extras**: WebSocket frame capture, session diff (anon vs logged-in to find
  gated endpoints), storage inventory, source-map recovery, CVE lookup for
  detected library versions.

## How it works

```
You:  open browser → log in → click through the flow → "done"
Skill: attach CDP (read-only) → capture API calls → summarize & infer schemas
       → grab the page .js → correlate → write the documentation
```

1. Launches Chrome with a debug port and an isolated profile.
2. Arms a passive CDP sniffer (`scripts/cdp_sniff.py`) that follows every tab.
3. You navigate and log in. Nothing is sent on your behalf.
4. On your signal, it summarizes the capture, pulls the bundle, and writes docs.

## Quick start

Requires [Claude Code](https://claude.com/claude-code), a Chromium-family
browser, Python 3, and `pip install websocket-client`.

```bash
# install as a personal skill
git clone https://github.com/<you>/site-recon ~/.claude/skills/site-recon
pip install websocket-client
```

Then just ask Claude Code:

> "Monitor my navigation on example.com and document its API."

or invoke it directly with `/site-recon`.

## Bug-bounty mode (optional, passive)

For **authorized** programs, `scripts/passive_findings.py` triages the data you
already captured and warns you only when something **critical** shows up —
secrets in the bundle, `alg=none` JWTs, tokens/PII in URLs, verbose error
disclosure, permissive CORS, IDOR *candidates*. It flags for manual review; it
never exploits, fuzzes, or enumerates. See
[`references/security-findings.md`](references/security-findings.md).

## The hard boundary

This tool is legitimate because it stays passive:

- It **observes your own navigation** — it does not drive the browser, send,
  replay, or automate requests against the site.
- Security findings are **candidates to verify manually, within an authorized
  scope** — never exploited.
- Credentials (tokens, cookies, passwords, OTP, PII) are **masked** in everything
  it saves. Captured sessions stay on your machine (see `.gitignore`).

Use it on sites you own or are authorized to test. Don't commit the `recon/`
output — it contains live tokens and personal data.

## Layout

```
site-recon/
├── SKILL.md                     # the skill Claude follows
├── scripts/
│   ├── cdp_sniff.py             # passive CDP network + WebSocket capture
│   ├── summarize_capture.py     # endpoint grouping + schema/enum inference
│   ├── to_openapi.py            # OpenAPI + Postman + .http export
│   ├── passive_findings.py      # critical-only passive security triage
│   ├── diff_sessions.py         # compare two sessions
│   ├── flow_diagram.py          # Mermaid sequence from timestamps
│   ├── unpack_sourcemaps.py     # recover original source from local maps
│   └── dump_storage.py          # localStorage/sessionStorage/cookie inventory
└── references/
    ├── documentation-template.md
    ├── rea-correlation.md
    ├── extras.md
    └── security-findings.md
```

## License

MIT. See `LICENSE`.
