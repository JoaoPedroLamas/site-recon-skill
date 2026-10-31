#!/usr/bin/env python3
"""
Export a site-recon capture to OpenAPI 3.0, a Postman collection, and a .http file.

Consumes live_capture.jsonl and writes importable artifacts so the user can
replay/inspect calls manually in Swagger UI, Postman, Insomnia, or VS Code REST
Client. Tokens are left as {{token}} placeholders — nothing is auto-sent.

Usage:
  python to_openapi.py --capture <dir>/live_capture.jsonl --out <dir> [--base https://host]
"""
import argparse, json, os, re, urllib.parse as up
from collections import defaultdict


def jbody(rec):
    pd = rec.get("post_data")
    if not pd:
        return None
    try:
        return json.loads(pd)
    except Exception:
        return None


def infer_schema(v):
    if isinstance(v, dict):
        return {"type": "object",
                "properties": {k: infer_schema(val) for k, val in list(v.items())[:80]}}
    if isinstance(v, list):
        return {"type": "array", "items": infer_schema(v[0]) if v else {}}
    if isinstance(v, bool):
        return {"type": "boolean"}
    if isinstance(v, (int, float)):
        return {"type": "number"}
    if v is None:
        return {"type": "null"}
    return {"type": "string"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default="")
    args = ap.parse_args()

    recs = [json.loads(l) for l in open(args.capture, encoding="utf-8") if l.strip()]
    recs = [r for r in recs if r.get("kind") != "websocket"]
    if not args.base and recs:
        m = re.match(r"(https?://[^/]+)", recs[0]["url"])
        args.base = m.group(1) if m else ""

    paths = defaultdict(dict)
    postman_items = []
    http_lines = []

    seen = set()
    for r in recs:
        u = r["url"]
        parsed = up.urlparse(u)
        path = parsed.path
        method = (r.get("method") or "GET").lower()
        q = up.parse_qs(parsed.query)
        # dedup by (method, path, sorted query keys, rpc method)
        rpcm = ""
        jb = jbody(r)
        if isinstance(jb, dict):
            rpcm = jb.get("method", "")
        sig = (method, path, rpcm)
        if sig in seen:
            continue
        seen.add(sig)

        op = {"summary": (rpcm or path), "parameters": [], "responses": {}}
        for k in q:
            op["parameters"].append({"name": k, "in": "query", "required": False,
                                     "schema": {"type": "string"},
                                     "example": q[k][0] if q[k] else ""})
        if jb is not None:
            op["requestBody"] = {"content": {"application/json": {"schema": infer_schema(jb)}}}
        # response
        rb = r.get("response_body")
        if rb:
            try:
                op["responses"][str(r.get("status", 200))] = {
                    "description": "captured",
                    "content": {"application/json": {"schema": infer_schema(json.loads(rb))}}}
            except Exception:
                op["responses"][str(r.get("status", 200))] = {
                    "description": "non-JSON (%s)" % r.get("mime")}
        else:
            op["responses"][str(r.get("status", 200))] = {"description": "captured"}
        paths[path][method] = op

        # postman
        postman_items.append({
            "name": (rpcm or (method.upper() + " " + path)),
            "request": {
                "method": method.upper(),
                "header": [{"key": "Authorization", "value": "{{token}}"},
                           {"key": "Content-Type", "value": "application/json"}],
                "url": {"raw": u, "host": [args.base], "path": path.strip("/").split("/"),
                        "query": [{"key": k, "value": (q[k][0] if q[k] else "")} for k in q]},
                "body": ({"mode": "raw", "raw": r.get("post_data")} if r.get("post_data") else None)}})

        # .http
        http_lines.append("### %s" % (rpcm or path))
        http_lines.append("%s %s" % (method.upper(), u))
        http_lines.append("Authorization: {{token}}")
        if r.get("post_data"):
            http_lines.append("Content-Type: application/json")
            http_lines.append("")
            http_lines.append(r.get("post_data"))
        http_lines.append("")

    openapi = {"openapi": "3.0.3",
               "info": {"title": "site-recon capture", "version": "0.1.0",
                        "description": "Generated from passive capture. Auth: bearer {{token}}."},
               "servers": [{"url": args.base}],
               "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
               "security": [{"bearer": []}],
               "paths": dict(paths)}

    json.dump(openapi, open(os.path.join(args.out, "openapi.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    json.dump({"info": {"name": "site-recon", "schema":
               "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
               "item": postman_items},
              open(os.path.join(args.out, "postman_collection.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    open(os.path.join(args.out, "requests.http"), "w", encoding="utf-8").write("\n".join(http_lines))
    print("wrote openapi.json, postman_collection.json, requests.http (%d operations)" % len(seen))


if __name__ == "__main__":
    main()
