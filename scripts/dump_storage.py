#!/usr/bin/env python3
"""
Dump localStorage / sessionStorage / cookie KEYS from the open page over CDP.

Reads the user's own browser state (the page they navigated). It reads, it does
not write or navigate. Values of secret-looking keys are masked; the point is to
document WHAT the app stores and which calls read/write it, not to harvest data.

Usage:
  python dump_storage.py --out <dir> [--cdp http://127.0.0.1:9222]
"""
import argparse, json, os, re, urllib.request
import websocket

SECRET_KEY = re.compile(r"(?i)(token|auth|session|senha|password|cpf|secret|jwt|refresh)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--cdp", default="http://127.0.0.1:9222")
    args = ap.parse_args()

    ver = json.load(urllib.request.urlopen(args.cdp + "/json/version", timeout=5))
    # pick first http(s) page target
    tgt = None
    for t in json.load(urllib.request.urlopen(args.cdp + "/json", timeout=5)):
        if t.get("type") == "page" and t.get("url", "").startswith("http"):
            tgt = t
            break
    if not tgt:
        print("no page target open")
        return
    ws = websocket.create_connection(tgt["webSocketDebuggerUrl"], suppress_origin=True)
    _id = [0]

    def call(method, params=None):
        _id[0] += 1
        ws.send(json.dumps({"id": _id[0], "method": method, "params": params or {}}))
        while True:
            m = json.loads(ws.recv())
            if m.get("id") == _id[0]:
                return m.get("result", {})

    js = """(() => {
      const dump = s => Object.fromEntries(Object.keys(s).map(k => [k, String(s.getItem(k)).length + ' chars']));
      return JSON.stringify({local: dump(localStorage), session: dump(sessionStorage), url: location.href});
    })()"""
    res = call("Runtime.evaluate", {"expression": js, "returnByValue": True})
    data = json.loads(res.get("result", {}).get("value", "{}"))

    def mask(d):
        return {k: ("[secret, %s]" % v if SECRET_KEY.search(k) else v) for k, v in (d or {}).items()}

    out = {"url": data.get("url"),
           "localStorage": mask(data.get("local")),
           "sessionStorage": mask(data.get("session"))}
    # cookies (names only + flags)
    ck = call("Network.getCookies", {})
    out["cookies"] = [{"name": c["name"], "httpOnly": c.get("httpOnly"),
                       "secure": c.get("secure"), "sameSite": c.get("sameSite")}
                      for c in ck.get("cookies", [])]
    os.makedirs(args.out, exist_ok=True)
    p = os.path.join(args.out, "storage_inventory.json")
    json.dump(out, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("wrote %s (local:%d session:%d cookies:%d)" %
          (p, len(out["localStorage"]), len(out["sessionStorage"]), len(out["cookies"])))


if __name__ == "__main__":
    main()
