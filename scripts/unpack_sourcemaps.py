#!/usr/bin/env python3
"""
Unpack source maps that are ALREADY on disk into original source trees.

Does NOT fetch anything from the network. It processes:
  - local .map files in the bundle dir, and
  - inline sourceMappingURL=data:... maps embedded in local .js files.

For remote .map URLs, either have the user save the .map via their browser, or
use the `reverse-engineer-anything` skill's analyze_web_bundle with
fetch_source_maps against the user's own open page — not this script.

Usage:
  python unpack_sourcemaps.py --bundle <dir> --out <dir>/sources
"""
import argparse, base64, glob, json, os, re


def write_sources(mp, out):
    n = 0
    sources = mp.get("sources") or []
    contents = mp.get("sourcesContent") or []
    for i, src in enumerate(sources):
        if i >= len(contents) or contents[i] is None:
            continue
        rel = re.sub(r"^(\.\.?/)+", "", src).replace("webpack://", "").lstrip("/")
        rel = re.sub(r"[?#].*$", "", rel) or ("source_%d.js" % i)
        dest = os.path.join(out, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        open(dest, "w", encoding="utf-8", errors="ignore").write(contents[i])
        n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    total = 0

    for f in glob.glob(os.path.join(args.bundle, "**", "*.map"), recursive=True):
        try:
            total += write_sources(json.load(open(f, encoding="utf-8")), args.out)
        except Exception as e:
            print("skip %s: %s" % (f, e))

    for f in glob.glob(os.path.join(args.bundle, "**", "*.js"), recursive=True):
        try:
            txt = open(f, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        m = re.search(r"sourceMappingURL=data:application/json;(?:charset=[^;]+;)?base64,([A-Za-z0-9+/=]+)", txt)
        if m:
            try:
                total += write_sources(json.loads(base64.b64decode(m.group(1))), args.out)
            except Exception as e:
                print("skip inline map in %s: %s" % (f, e))

    print("recovered %d original source files into %s" % (total, args.out))
    if total == 0:
        print("no local source maps found — save the .map via the browser, or use REA fetch_source_maps")


if __name__ == "__main__":
    main()
