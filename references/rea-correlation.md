# Correlating captured requests to the bundle (static↔runtime)

Goal: for each endpoint in the capture, find the exact line in the page's
JavaScript that builds and sends it, so the doc explains *how* to construct the
call (param order, headers, token) and *where in the flow* it fires.

## Quick path (works even without REA)

Most web apps send via `$http`, `$.ajax`, `axios`, or a thin wrapper — REA's
request extractor (fetch/WebSocket/node:http only) won't see these. Direct
source reading is usually faster:

1. From the capture, take the endpoint's distinctive string: the REST path
   (`tickets/booking`), the RPC `class.method` (`SuperIngresso.getProdutosLugar`),
   or a query key.
2. Grep the bundle for it:
   - `grep -n "getProdutosLugar" bundle.js`
   - `grep -n "tickets/booking" bundle.js`
3. Read around the hit. Identify:
   - the **call wrapper** (e.g. `ajax(class, method, params)` /
     `ajaxrest(url, method, data)`), its URL construction, and header logic;
   - the **param list** — what each positional/body field is and where its value
     comes from (a prior response field, a DOM selection, config);
   - **token handling** — which header, read from where, refreshed from which
     response header.
4. Record the `file:line` for the doc's "Where it fires" and parameter table.

## Finding the shared transport layer

Locate the one or two functions every call goes through and document them once:
- Search for the router/base URL (`router.php`, `/api/`, an `axios.create`), the
  `Authorization` header assignment, and the response-envelope handling
  (`data.result` / `data.error`).
- Error-code branches here (login-required, queue, proof-of-work, WAF) belong in
  the doc's Defenses section — they apply to every endpoint.

## When to use REA

Worth it for large or heavily minified bundles where grep context is unreadable:

1. Copy bundle files into a folder; give them a `.js` extension if needed.
2. `analyze_javascript_application` with `detail: "summary"` and a raised
   `max_heap_mb` for big files. Keep the returned `parent_evidence_id`.
3. `trace_application_feature` with a `string` seed (the endpoint literal) to see
   reachable modules, or `inspect_analysis_view` to page modules.
4. If the worker exhausts heap or the trace returns no-match (common when the
   call isn't fetch-based), fall back to the grep path above — that's expected,
   not a failure.

REA shines for: module structure, data-flow of a value, comparing two bundle
versions, and confirming a function's shape. It does not replace reading the
call wrapper for `$http`/`$.ajax` apps.

## Output

For each endpoint, the doc should end up with:
- `file:line` of the call site and of the shared wrapper;
- the mapping "param N ← source" (prior response field / user input / config);
- any per-endpoint header or option (e.g. grouped vs. single, progbar off).
