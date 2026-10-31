#!/usr/bin/env python3
"""
Passive CDP network sniffer for site-recon.

Attaches to a running Chrome/Chromium over the DevTools Protocol and records
request+response pairs for API-like calls while the USER drives the browser.
It never navigates, clicks, or sends requests itself — pure observation.

Uses browser-level auto-attach (flatten) so it follows every tab and every
navigation, including new targets, without re-attaching by hand.

Requires: websocket-client  (pip install websocket-client)

Usage:
  python cdp_sniff.py --out <dir> [--cdp http://127.0.0.1:9222]
                      [--minutes 60] [--include REGEX] [--exclude REGEX]

Writes:
  <out>/live_capture.jsonl   one JSON record per captured call (credentials masked)
  <out>/sniff.log            attach + per-call log

Stop it with Ctrl-C or by killing the process; records are flushed as they arrive.
"""
import argparse, json, re, sys, time, urllib.request
import websocket  # websocket-client

DEFAULT_INCLUDE = r"(router\.php|/api/|/rest/|/graphql|/tickets/|/login|/logins|/auth|/oauth|/session|/cart|/checkout|/products?|/items?|/booking|/payment|/users?|/account|/search|/config|\.json(\?|$))"
DEFAULT_EXCLUDE = r"\.(js|mjs|css|png|jpe?g|svg|gif|webp|ico|woff2?|ttf|eot|mp4|webm|map)(\?|$)|/tiles?/|google-analytics|googletagmanager|doubleclick|facebook|hotjar|/gtm\.|/collect\b"

SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "authorization_refresh_token",
                  "x-api-key", "x-auth-token", "x-csrf-token", "proxy-authorization"}
SECRET_BODY_KEYS = {"_username", "_codigo", "_password", "password", "senha", "pwd",
                    "token", "access_token", "refresh_token", "otp", "codigo",
                    "cpf", "email", "credit_card", "card", "cvv"}


def get_json(url):
    return json.load(urllib.request.urlopen(url, timeout=5))


def mask_headers(h):
    out = {}
    for k, v in (h or {}).items():
        out[k] = "[REDACTED]" if k.lower() in SECRET_HEADERS else v
    return out


def mask_body(s):
    if not s:
        return s
    try:
        j = json.loads(s)
    except Exception:
        return s  # non-JSON body kept as-is (may be form/doc) — caller still masks in summary

    def scrub(o):
        if isinstance(o, dict):
            return {k: ("[REDACTED]" if k.lower() in SECRET_BODY_KEYS else scrub(v)) for k, v in o.items()}
        if isinstance(o, list):
            return [scrub(x) for x in o]
        return o
    return json.dumps(scrub(j), ensure_ascii=False)


def mask_response(s):
    if not s:
        return s
    # redact common token fields inside response bodies regardless of nesting
    s = re.sub(r'("(?:access_token|refresh_token|authorization|token)"\s*:\s*")[^"]+(")',
               r"\1[REDACTED]\2", s)
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--cdp", default="http://127.0.0.1:9222")
    ap.add_argument("--minutes", type=float, default=60)
    ap.add_argument("--include", default=DEFAULT_INCLUDE)
    ap.add_argument("--exclude", default=DEFAULT_EXCLUDE)
    args = ap.parse_args()

    inc = re.compile(args.include, re.I)
    exc = re.compile(args.exclude, re.I)
    import os
    os.makedirs(args.out, exist_ok=True)
    cap_path = os.path.join(args.out, "live_capture.jsonl")
    log_path = os.path.join(args.out, "sniff.log")
    fout = open(cap_path, "a", encoding="utf-8")

    def log(m):
        open(log_path, "a", encoding="utf-8").write(m + "\n")

    ver = get_json(args.cdp + "/json/version")
    ws = websocket.create_connection(ver["webSocketDebuggerUrl"], max_size=None, suppress_origin=True)
    log("attached to %s" % ver.get("Browser"))

    _id = [0]

    def send(method, params=None, session=None):
        _id[0] += 1
        msg = {"id": _id[0], "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        ws.send(json.dumps(msg))
        return _id[0]

    # Follow every current and future tab.
    send("Target.setDiscoverTargets", {"discover": True})
    send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True})

    reqs = {}            # (session, requestId) -> record
    body_cmd = {}        # commandId -> (session, requestId)
    post_cmd = {}        # commandId -> (session, requestId)
    ws_urls = {}         # (session, requestId) -> websocket url

    def write_rec(key):
        r = reqs.get(key)
        if not r or r.get("_w"):
            return
        r["_w"] = True
        rec = {k: v for k, v in r.items() if not k.startswith("_")}
        fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fout.flush()
        log("SAVED %s %s %s" % (rec.get("method"), rec.get("status"), rec.get("url", "")[:100]))

    t_end = time.time() + args.minutes * 60
    ws.settimeout(2)
    while time.time() < t_end:
        try:
            msg = json.loads(ws.recv())
        except websocket.WebSocketTimeoutException:
            continue
        except Exception as e:
            log("recv err %s" % e)
            break

        sess = msg.get("sessionId")

        if msg.get("method") == "Target.attachedToTarget":
            p = msg["params"]
            s = p["sessionId"]
            send("Network.enable", {"maxTotalBufferSize": 100_000_000, "maxResourceBufferSize": 50_000_000}, session=s)
            send("Runtime.runIfWaitingForDebugger", session=s)
            log("attached target %s %s" % (p["targetInfo"].get("type"), p["targetInfo"].get("url", "")[:80]))
            continue

        if "method" in msg:
            m = msg["method"]
            p = msg.get("params", {})
            if m == "Network.requestWillBeSent":
                url = p["request"]["url"]
                if not inc.search(url) or exc.search(url):
                    continue
                key = (sess, p["requestId"])
                reqs[key] = {
                    "url": url,
                    "method": p["request"]["method"],
                    "resource_type": p.get("type"),
                    "request_headers": mask_headers(p["request"].get("headers")),
                    "post_data": mask_body(p["request"].get("postData")),
                    "has_post_data": p["request"].get("hasPostData", False),
                    "ts": p.get("wallTime"),
                }
                if reqs[key]["has_post_data"] and not reqs[key]["post_data"]:
                    post_cmd[send("Network.getRequestPostData", {"requestId": p["requestId"]}, session=sess)] = key
            elif m == "Network.responseReceived":
                key = (sess, p["requestId"])
                if key in reqs:
                    reqs[key]["status"] = p["response"]["status"]
                    reqs[key]["response_headers"] = mask_headers(p["response"].get("headers"))
                    reqs[key]["mime"] = p["response"].get("mimeType")
            elif m == "Network.loadingFinished":
                key = (sess, p["requestId"])
                if key in reqs:
                    body_cmd[send("Network.getResponseBody", {"requestId": p["requestId"]}, session=sess)] = key
            elif m == "Network.loadingFailed":
                key = (sess, p["requestId"])
                if key in reqs:
                    reqs[key]["failed"] = p.get("errorText")
                    write_rec(key)
            elif m == "Network.webSocketCreated":
                ws_urls[(sess, p["requestId"])] = p.get("url", "")
            elif m in ("Network.webSocketFrameSent", "Network.webSocketFrameReceived"):
                url = ws_urls.get((sess, p["requestId"]), "")
                payload = (p.get("response") or {}).get("payloadData", "")
                rec = {
                    "kind": "websocket",
                    "url": url,
                    "direction": "sent" if m.endswith("Sent") else "received",
                    "opcode": (p.get("response") or {}).get("opcode"),
                    "payload": mask_response(mask_body(payload[:4000])),
                    "ts": p.get("timestamp"),
                }
                fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fout.flush()
        elif "id" in msg:
            cid = msg["id"]
            if cid in body_cmd:
                key = body_cmd.pop(cid)
                res = msg.get("result", {})
                if res.get("base64Encoded"):
                    reqs[key]["response_body_base64_len"] = len(res.get("body", ""))
                else:
                    reqs[key]["response_body"] = mask_response(res.get("body"))
                write_rec(key)
            elif cid in post_cmd:
                key = post_cmd.pop(cid)
                res = msg.get("result", {})
                if key in reqs and "postData" in res:
                    reqs[key]["post_data"] = mask_body(res["postData"])

    fout.close()
    log("done")


if __name__ == "__main__":
    main()
