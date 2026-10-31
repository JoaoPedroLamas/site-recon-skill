#!/usr/bin/env python3
"""
Build a Mermaid sequence diagram of the captured flow, ordered by timestamp.

Gives the documentation a visual "login -> ... -> checkout" sequence derived
from when calls actually happened. Reads only the capture file.

Usage:
  python flow_diagram.py --capture <dir>/live_capture.jsonl [--out <dir>/flow.mmd]

Prints the Mermaid source; also writes it if --out is given. Hand the .mmd to the
`dataviz` skill (or any Mermaid renderer) for a styled picture.
"""
import argparse, json, re, urllib.parse as up


def label(r):
    u = r["url"]
    q = up.parse_qs(u.split("?", 1)[1]) if "?" in u else {}
    rpcm = q.get("method", [""])[0]
    try:
        jb = json.loads(r.get("post_data") or "")
        if isinstance(jb, dict) and jb.get("method"):
            rpcm = jb["method"]
    except Exception:
        pass
    if rpcm:
        return (q.get("class", [""])[0] + "." + rpcm).strip(".")
    path = re.sub(r"https?://[^/]+", "", u.split("?", 1)[0])
    path = re.sub(r"/[0-9a-f]{16,}", "/{id}", path)
    return r.get("method", "?") + " " + path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()
    recs = [json.loads(l) for l in open(args.capture, encoding="utf-8") if l.strip()]
    recs = [r for r in recs if r.get("kind") != "websocket" and r.get("ts")]
    recs.sort(key=lambda r: r.get("ts") or 0)

    lines = ["sequenceDiagram", "    participant U as User/Browser", "    participant S as Server"]
    last = None
    for r in recs:
        lab = label(r).replace(":", " ")
        lines.append("    U->>S: %s" % lab)
        st = r.get("status")
        note = ("error %s" % st) if (isinstance(st, int) and st >= 400) else "%s" % st
        lines.append("    S-->>U: %s" % note)
    out = "\n".join(lines)
    print(out)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(out)
        print("\n[wrote %s]" % args.out)


if __name__ == "__main__":
    main()
