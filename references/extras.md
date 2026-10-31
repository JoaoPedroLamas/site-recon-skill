# Extras: exports, diffs, storage, source maps, visuals, CVE enrichment

Run these after the base capture + summarize steps. All read only
already-captured data or local files unless noted; none send requests to the
target site.

## OpenAPI + Postman + .http export
Turn the capture into importable API artifacts (bearer token left as
`{{token}}` placeholder — nothing auto-sends):
```
python <skill>/scripts/to_openapi.py --capture recon/live_capture.jsonl --out recon
```
Writes `recon/openapi.json` (import in Swagger UI / Insomnia), `postman_collection.json`,
and `requests.http` (VS Code REST Client). Mention these in the doc so a consumer
can replay calls manually.

## WebSocket / SSE / GraphQL
The sniffer already records WebSocket frames (`kind:"websocket"` lines, payloads
masked+truncated) and any GraphQL HTTP call (POST body with `query`). For GraphQL,
document the operation names and variable shapes from the captured bodies; if the
server exposes introspection the user can trigger it by navigating, then it's in
the capture. SSE (`text/event-stream`) shows up as a normal captured response.

## Session diff (find auth/role-gated endpoints)
Capture two sessions into different dirs (e.g. `recon-anon/`, `recon-auth/`), then:
```
python <skill>/scripts/diff_sessions.py --a recon-anon/live_capture.jsonl --b recon-auth/live_capture.jsonl
```
"Only in B" after login = auth-gated calls. Great for a complete endpoint map.

## Storage inventory
Document what the app persists and which calls read/write it (keys only; secret
values masked). Needs the page still open on CDP:
```
python <skill>/scripts/dump_storage.py --out recon
```
Writes `recon/storage_inventory.json` (localStorage/sessionStorage keys, cookie
names + flags). Cross-reference with the bundle (e.g. `localStorage.getItem("access_token")`).

## Source maps → original source
If the bundle ships source maps, recovering original (unminified) source makes
the doc far more precise:
```
python <skill>/scripts/unpack_sourcemaps.py --bundle recon/bundle --out recon/bundle/sources
```
Handles local `.map` files and inline `data:` maps. For remote `.map` URLs, have
the user save them via the browser, or use REA `analyze_web_bundle` with
`fetch_source_maps` on the user's own open page — never fetch them from a script.

## Flow diagram
```
python <skill>/scripts/flow_diagram.py --capture recon/live_capture.jsonl --out recon/flow.mmd
```
Emits a Mermaid sequence diagram ordered by timestamp. Embed the `.mmd` in the
doc, or hand it to the `dataviz` skill for a styled picture / an endpoint map.

## CVE / stack enrichment
From the bundle, identify libraries and versions (banners like `jQuery v3.7.1`,
`AngularJS`, server headers). Then use **WebSearch** to check for known CVEs of
those exact versions and note them in the doc's Defenses/Notes section. This is
public-info research, not probing the target.

## Publish the documentation
When the doc is for a team or needs to be shareable, publish it as an artifact
(a navigable page, Swagger-UI-like) instead of leaving it as a local `.md` —
use the artifacts tooling. Keep credentials out of anything published.
