#!/usr/bin/env python3
"""
Diff two site-recon captures (e.g. anonymous vs logged-in, before vs after stock).

Reveals endpoints/fields that appear only in one session — useful to find
auth-gated or role-gated calls. Purely reads two capture files.

Usage:
  python diff_sessions.py --a <dir1>/live_capture.jsonl --b <dir2>/live_capture.jsonl
"""
import argparse, json, re, urllib.parse as up


def endpoints(path):
    eps = {}
    for l in open(path, encoding="utf-8"):
        if not l.strip():
            continue
        r = json.loads(l)
        if r.get("kind") == "websocket":
            eps.setdefault("WS " + r.get("url", ""), r)
            continue
        u = r["url"]
        path_only = re.sub(r"https?://[^/]+", "", u.split("?", 1)[0])
        path_only = re.sub(r"/[0-9a-f]{16,}", "/{id}", path_only)
        path_only = re.sub(r"/\d+", "/{id}", path_only)
        q = up.parse_qs(u.split("?", 1)[1]) if "?" in u else {}
        rpcm = q.get("method", [""])[0]
        try:
            jb = json.loads(r.get("post_data") or "")
            if isinstance(jb, dict) and jb.get("method"):
                rpcm = jb["method"]
        except Exception:
            pass
        key = ("RPC " + q.get("class", [""])[0] + "." + rpcm) if rpcm else (r.get("method", "?") + " " + path_only)
        eps[key] = r
    return eps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True)
    ap.add_argument("--b", required=True)
    args = ap.parse_args()
    A, B = endpoints(args.a), endpoints(args.b)
    only_a = sorted(set(A) - set(B))
    only_b = sorted(set(B) - set(A))
    both = sorted(set(A) & set(B))
    print("# Session diff\n")
    print("## Only in A (%d)" % len(only_a))
    for e in only_a:
        print("- " + e)
    print("\n## Only in B (%d)" % len(only_b))
    for e in only_b:
        print("- " + e)
    print("\n## In both (%d)" % len(both))
    for e in both:
        print("- " + e)


if __name__ == "__main__":
    main()
