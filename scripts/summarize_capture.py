#!/usr/bin/env python3
"""
Summarize a site-recon capture into an API inventory with inferred schemas.

Reads live_capture.jsonl (from cdp_sniff.py), groups calls by endpoint, infers
request/response field shapes across all samples of each endpoint, and prints a
compact inventory the documentation step builds on. It also writes per-endpoint
response samples as JSON files for reference.

Usage:
  python summarize_capture.py --capture <dir>/live_capture.jsonl --out <dir>

Prints the inventory to stdout and writes:
  <out>/samples/<endpoint-slug>.json   one representative response per endpoint
"""
import argparse, json, os, re, urllib.parse as up
from collections import defaultdict, Counter


def endpoint_key(rec):
    """Stable id for an endpoint. For RPC routers, key by class.method."""
    u = rec["url"]
    path = u.split("?", 1)[0]
    path = re.sub(r"https?://[^/]+", "", path)
    q = up.parse_qs(u.split("?", 1)[1]) if "?" in u else {}
    if "router.php" in path or q.get("class") or q.get("method"):
        cls = (q.get("class", [""])[0] or _body_class(rec))
        mth = (q.get("method", [""])[0] or _body_method(rec))
        if cls or mth:
            return "RPC %s.%s" % (cls, mth)
    # collapse numeric / hash ids in REST paths to {id}
    norm = re.sub(r"/[0-9a-f]{16,}", "/{id}", path)
    norm = re.sub(r"/\d+", "/{id}", norm)
    return "%s %s" % (rec.get("method", "?"), norm)


def _body_json(rec):
    pd = rec.get("post_data")
    if not pd:
        return None
    try:
        return json.loads(pd)
    except Exception:
        return None


def _body_class(rec):
    j = _body_json(rec)
    if isinstance(j, dict):
        return j.get("class", "")
    if isinstance(j, list) and j and isinstance(j[0], dict):
        return j[0].get("class", "")
    return ""


def _body_method(rec):
    j = _body_json(rec)
    if isinstance(j, dict):
        return j.get("method", "")
    if isinstance(j, list) and j and isinstance(j[0], dict):
        return j[0].get("method", "")
    return ""


def shape(v, depth=0, maxd=4):
    """Infer a compact type shape from a value."""
    if depth > maxd:
        return "..."
    if isinstance(v, dict):
        return {k: shape(val, depth + 1, maxd) for k, val in list(v.items())[:60]}
    if isinstance(v, list):
        if not v:
            return ["<empty>"]
        return ["array[%d]" % len(v), shape(v[0], depth + 1, maxd)]
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    return "string"


def merge_enum(values):
    """If a string field has few distinct short values across samples, treat as enum."""
    vals = [v for v in values if isinstance(v, str) and len(v) <= 12]
    c = Counter(vals)
    if 1 < len(c) <= 8 and len(vals) == len(values):
        return "enum{%s}" % "|".join(sorted(c))
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    recs = [json.loads(l) for l in open(args.capture, encoding="utf-8") if l.strip()]
    groups = defaultdict(list)
    for r in recs:
        groups[endpoint_key(r)].append(r)

    samples_dir = os.path.join(args.out, "samples")
    os.makedirs(samples_dir, exist_ok=True)

    print("# Capture inventory — %d calls, %d distinct endpoints\n" % (len(recs), len(groups)))
    for key in sorted(groups):
        g = groups[key]
        methods = Counter(r.get("method") for r in g)
        statuses = Counter(r.get("status") for r in g)
        mimes = Counter((r.get("mime") or "?") for r in g)
        print("## %s" % key)
        print("- samples: %d | http: %s | status: %s | mime: %s"
              % (len(g), dict(methods), dict(statuses), dict(mimes)))

        # request body shape (first with a body)
        for r in g:
            j = _body_json(r)
            if j is not None:
                print("- request_body: %s" % json.dumps(shape(j), ensure_ascii=False))
                break
        # also GET query params
        q_keys = set()
        for r in g:
            if "?" in r["url"]:
                q_keys |= set(up.parse_qs(r["url"].split("?", 1)[1]).keys())
        q_keys -= {"class", "method", "lang"}
        if q_keys:
            print("- query_params: %s" % sorted(q_keys))

        # response shape + save sample
        resp_obj = None
        for r in g:
            rb = r.get("response_body")
            if rb is None:
                continue
            try:
                resp_obj = json.loads(rb)
                break
            except Exception:
                print("- response: NON-JSON (%s), %d bytes — document how to parse" %
                      (r.get("mime"), len(rb)))
                resp_obj = None
                break
        if resp_obj is not None:
            print("- response_body: %s" % json.dumps(shape(resp_obj), ensure_ascii=False)[:1200])
            slug = re.sub(r"[^a-zA-Z0-9]+", "-", key).strip("-")[:80]
            json.dump(resp_obj, open(os.path.join(samples_dir, slug + ".json"), "w", encoding="utf-8"),
                      ensure_ascii=False, indent=1)
        print()


if __name__ == "__main__":
    main()
