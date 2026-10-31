# Documentation template (site-recon output)

Produce a single Markdown file. Target: a reader understands the whole backend
from this doc alone — like an official, documented Swagger. Match the user's
language. Cite evidence everywhere: `bundle.js:1461` for code, `samples/<x>.json`
for responses. Separate **observed** (captured/returned) from **inferred** (read
from code) from **unknown** (not captured).

Use this structure:

## 1. Overview & method
- Host(s), app stack (framework, libs) if identifiable from the bundle.
- How the data was gathered: passive CDP capture of user-driven navigation +
  static bundle analysis. State plainly that nothing was automated/replayed.
- List source files: capture jsonl, `samples/`, bundle files, line-ref base.

## 2. Transport
- The call style(s): REST, RPC-over-POST, GraphQL, etc. For each, the exact URL
  shape, how params/body are serialized, required headers, and the response
  envelope (e.g. `{result, error:{code,message}}`). Note batching/grouping if any.

## 3. Authentication & session
- The full login flow, step by step (e.g. OTP: list providers → send code →
  submit code → token). Request bodies and the success/error shapes.
- Token format and lifetime (decode JWT claims if present: `exp`, bindings to
  UA/IP). **Token rotation**: which responses mint a new token and where the
  client stores it — a caller must refresh accordingly.

## 4. End-to-end flow
- The reconstructed sequence from the session (use capture timestamps), as a
  compact diagram or numbered list: what triggers what, and which response field
  feeds the next request's params.

## 5. Endpoints (the Swagger-like core)
One subsection per endpoint, grouped by resource/class. For each:
- **Name / route** and HTTP method.
- **Where it fires**: `file:line` in the bundle + the user action.
- **Parameters**: table of name, position/location (path/query/body/positional),
  type, required?, how to fill it (where the value comes from — e.g. "the
  `idmapa_bloco_fis` from a `carregarBlocos` entry").
- **Request example** (masked).
- **Response**: schema with types and observed `enum{...}` values; link the
  sample file. If the response is **not JSON** (HTML, redirect, binary, doc),
  say so and document how the client consumes it instead of inventing a schema.
- **Errors**: observed error codes and what the client does for each.

## 6. Defenses & edge behavior
- WAF, bot checks, virtual queue, proof-of-work, captcha, rate limits — trigger
  conditions and how the client responds. If a proof-of-work exists, document
  the algorithm (input, difficulty meaning, where it's attached).

## 7. Gaps
- Honest list of endpoints/states not captured and why (e.g. "no stock → never
  reached add-to-cart"). For each, say what navigation would capture it. Never
  fill a gap by sending the call yourself.

## 8. Quick reference for a consumer
- Minimal ordered recipe to go from zero to the main action, the critical
  gotchas (token rotation, required headers, defenses), and expiry/timeout notes.

## Writing rules
- Prefer tables for params and status/error codes.
- Keep code/paths/numbers verbatim.
- One idea per row; mark every value as observed/inferred/unknown.
