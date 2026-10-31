---
name: site-recon
description: >-
  Document how a website's backend works by passively watching the user's own
  browsing. Use this whenever the user wants to map, reverse-engineer, or write
  documentation for a site's API, endpoints, request/response formats, auth flow,
  or page .js — especially when they say things like "monitor my navigation",
  "capture the requests while I browse", "document how this site's API works",
  "make a Swagger/OpenAPI-style doc from my session", "analyze the page's
  JavaScript and the calls it makes", or "I'll browse and you figure out the
  backend". The user drives a real browser and logs in themselves; this skill
  only observes (CDP network capture) and analyzes the captured traffic plus the
  page bundle, then produces official-style API documentation. It never
  automates, replays, or sends requests on its own. Prefer this skill over
  ad-hoc DevTools/HAR work for session-to-documentation tasks.
---

# site-recon

Turn a real, user-driven browsing session into **official-style API
documentation**: every endpoint, how to call it, what it needs, what it returns
(JSON or not), the auth flow, and the defenses — enough that someone could
understand the whole site from the doc alone, like a documented Swagger.

## The non-negotiable boundary

This skill is **passive observation of the user's own navigation**, for
documentation. The user opens the browser, logs in, and clicks through the site
themselves. Your sniffer only *reads* the network traffic the user generates.

- **Never** send, replay, or automate requests against the live site. No bots,
  no scripted logins, no "just re-run that call to see the response."
- If a response wasn't captured because the user didn't reach that state (e.g.
  no stock, an error path), document it as a gap and offer to capture it next
  time the user navigates there. Do not fill the gap by firing the call.
- Credentials (tokens, cookies, passwords, OTP, PII) are masked in everything
  you save. The raw session stays on the user's machine.

This boundary is what makes the activity legitimate. Keep it.

## Workflow

Work in the project's working directory. Put captures and docs under
`recon/` (create it): `recon/live_capture.jsonl`, `recon/samples/`,
`recon/bundle/`, and the final `recon/API_DOCUMENTATION.md` (match the user's
language and preferred filename).

### 1. Start the browser with remote debugging

The sniffer attaches over the Chrome DevTools Protocol (CDP), so Chrome must
expose a debug port. Launch it yourself (background) with an isolated profile so
the user's main browser is untouched:

```
chrome.exe --remote-debugging-port=9222 --user-data-dir="<temp>/recon-chrome" about:blank
```

Find Chrome's path per OS (Windows: `C:\Program Files\Google\Chrome\Application\chrome.exe`;
macOS: `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`; Linux:
`google-chrome`). Confirm CDP is up: `curl -s http://127.0.0.1:9222/json/version`.
If the user already runs Chrome with a debug port, just use it.

### 2. Arm the sniffer (background) before the user navigates

```
python <skill>/scripts/cdp_sniff.py --out recon --minutes 60
```

Run it with `run_in_background`. It attaches to **all** tabs and follows
navigations (auto-attach flatten), so it keeps working across logins and SPA
route changes. Check `recon/sniff.log` shows `attached`. Tune what counts as an
API call with `--include`/`--exclude` (regex); defaults catch `router.php`,
`/api/`, REST paths, auth, cart/checkout, `.json`, and skip static assets,
tiles, analytics. It only records from attach onward — tell the user to (re)do
any step whose call you need.

### 3. Let the user drive — then wait for their signal

Tell the user to do the whole flow they care about (login → browse → the key
actions) at their own pace, and to tell you when done. **Do not poll** the
capture or fake progress. The browser records continuously; you process when
they say they've finished. If they ask, you can read `recon/sniff.log` or
`tail` the jsonl to show what's landed.

### 4. Stop the sniffer and summarize

Kill the background sniffer. Then build the inventory:

```
python <skill>/scripts/summarize_capture.py --capture recon/live_capture.jsonl --out recon
```

This groups calls by endpoint (RPC routers keyed by `class.method`, REST by
normalized path), infers request/response shapes across all samples, flags
enums and non-JSON responses, and writes one representative response per
endpoint to `recon/samples/`. Read its output — it's your skeleton.

### 5. Grab the page JavaScript

Save the page's main bundle(s) and any interesting workers to `recon/bundle/`.
Easiest: have the user "Save as" / you fetch the already-loaded script URLs seen
in the capture, or copy from the browser. The bundle explains *how* each call is
built (params, headers, token handling) and *where* in the flow it fires.

### 6. Analyze with REA when the bundle is big or minified

For a large/minified bundle, use the `reverse-engineer-anything` skill (REA):
`analyze_javascript_application` on `recon/bundle/` (use `detail: "summary"` and
raise `max_heap_mb` for big files), then `trace_application_feature` /
`inspect_analysis_view` to follow a specific endpoint string. REA's request
extractor only sees `fetch`/`WebSocket`/`node:http` — most web apps use
`$http`/`$.ajax`/`axios`, so **fall back to direct source reading** (grep the
bundle for the endpoint string, the call wrapper, the header/token logic). See
`references/rea-correlation.md` for correlating each captured request to its
`file:line` in the bundle — this is what makes the doc explain the *why*, not
just the *what*.

### 6b. Extras (exports, diffs, storage, visuals) — as useful

After the inventory, enrich the recon with the add-ons in `references/extras.md`
(read it for exact commands). All are passive — they read captured data or local
files, never hitting the site:
- **OpenAPI + Postman + .http** (`scripts/to_openapi.py`): importable API specs,
  token left as `{{token}}`.
- **Session diff** (`scripts/diff_sessions.py`): compare two captures (anon vs
  logged-in) to surface auth/role-gated endpoints.
- **Storage inventory** (`scripts/dump_storage.py`): localStorage/sessionStorage
  keys + cookie names (needs the page still open; secrets masked).
- **Source maps** (`scripts/unpack_sourcemaps.py`): recover original source from
  local `.map`/inline maps for a far more precise doc.
- **Flow diagram** (`scripts/flow_diagram.py`): Mermaid sequence from timestamps;
  style it with the `dataviz` skill.
- **CVE enrichment**: identify lib/server versions from the bundle, then
  **WebSearch** known CVEs for those versions.
- **Publish**: for a shareable/team doc, publish as an artifact (Swagger-UI-like
  page), credentials excluded.
- WebSocket/SSE/GraphQL are captured automatically (see `references/extras.md`).

### 6c. Passive security triage (optional, authorized scope only)

If the user wants bug-bounty help, run the **strictly passive** triage over the
already-captured data and **proactively alert them only on CRITICAL/HIGH**:

```
python <skill>/scripts/passive_findings.py --capture recon/live_capture.jsonl --bundle recon/bundle
```

Read `references/security-findings.md` first — it defines the hard boundary
(passive only; flag candidates, never exploit/fuzz/enumerate; authorized targets
only). Lower-severity items go in a collapsible "Security notes" section of the
doc; never include a working exploit.

### 7. Write the documentation

Follow `references/documentation-template.md` exactly. The goal: a reader
understands the entire site from this doc. Cover transport, auth flow, every
endpoint (params, how to fill them, response schema with observed enums,
non-JSON handling), the end-to-end flow reconstructed from timestamps, defenses
(WAF, queue, proof-of-work, captcha, token rotation), and an honest gaps list.
Cite evidence: `file:line` for code, sample filenames for responses.

### 8. Sanitize and hand off

Confirm no live credentials remain in saved files (the scripts mask on capture;
double-check `recon/live_capture.jsonl` and `recon/samples/`). Tell the user the
Chrome debug profile can be closed, and summarize what was captured vs. what's
still a gap.

## Improvement ideas already built in

- **Static↔runtime correlation** (step 6): map each request to the bundle line
  that builds it.
- **Swagger-like grouping** (step 4): endpoints grouped by resource/method with
  param and schema tables.
- **Schema + enum inference** (step 4): shapes merged across samples; repeated
  short string values become `enum{...}` (e.g. `idstatus: L|R|O|B`).
- **Non-JSON handling**: HTML/binary/redirect responses are flagged, not forced
  into JSON.
- **Auth & defenses section**: login/OTP, token rotation, PoW, WAF, queue,
  captcha get their own documented section.
- **Credential masking**: always, on capture and in samples.
- **Dedup + variation notes**: repeated calls merged; differences noted.
- **Flow reconstruction**: sequence rebuilt from timestamps.

## Requirements

- `websocket-client` (`pip install websocket-client`) for the sniffer.
- A Chromium-family browser reachable over CDP.
- Optional: the `reverse-engineer-anything` skill for heavy bundle analysis.
