#!/usr/bin/env python3
"""
Passive security triage over an already-captured site-recon session.

STRICTLY PASSIVE. It reads only what the user already captured by browsing
(live_capture.jsonl) and, optionally, locally-saved bundle files. It sends
nothing, tests nothing, exploits nothing. It flags *candidates* for a human to
verify within an authorized scope (bug-bounty program / permitted pentest).

By default it prints ONLY findings rated CRITICAL or HIGH, so the operator is
alerted just when something serious shows up. Use --all to see every severity.

Usage:
  python passive_findings.py --capture <dir>/live_capture.jsonl [--bundle <dir>] [--all]

Exit code is 2 if any CRITICAL finding exists (handy for "warn me only if critical").
"""
import argparse, base64, glob, json, os, re, sys, urllib.parse as up

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("Stripe secret key", re.compile(r"sk_live_[0-9A-Za-z]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("Generic secret assignment", re.compile(r"(?i)(api[_-]?key|secret|client[_-]?secret|passwd|password)\s*[:=]\s*['\"][A-Za-z0-9/\+_\-]{12,}['\"]")),
]

SENSITIVE_QS = re.compile(r"(?i)\b(token|access_token|password|senha|cpf|secret|api[_-]?key|session|auth)\b")
SECURITY_HEADERS = ["content-security-policy", "strict-transport-security",
                    "x-frame-options", "x-content-type-options"]

findings = []  # (severity, title, detail)


def add(sev, title, detail):
    findings.append((sev, title, detail))


def b64url_json(seg):
    seg += "=" * (-len(seg) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg.encode()))
    except Exception:
        return None


def check_jwt(token, where):
    parts = token.split(".")
    if len(parts) != 3:
        return
    hdr = b64url_json(parts[0]) or {}
    pl = b64url_json(parts[1]) or {}
    alg = hdr.get("alg")
    if alg == "none":
        add("CRITICAL", "JWT alg=none", "%s accepts unsigned tokens" % where)
    if alg and alg.upper().startswith("HS"):
        add("LOW", "JWT uses HMAC (%s)" % alg,
            "%s — symmetric; fine unless the secret is weak/leaked" % where)
    exp, iat = pl.get("exp"), pl.get("iat")
    if isinstance(exp, int) and isinstance(iat, int):
        life = exp - iat
        if life > 86400:
            add("MEDIUM", "Long-lived JWT (%ds)" % life, "%s" % where)
    for k in ("ip", "email", "cpf", "password", "senha"):
        if k in pl:
            add("MEDIUM", "JWT carries sensitive claim '%s'" % k, "%s" % where)


def scan_capture(path):
    recs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    for r in recs:
        if r.get("kind") == "websocket":
            continue
        u = r["url"]
        qs = up.urlparse(u).query
        # secrets / PII in URL query
        if qs and SENSITIVE_QS.search(qs):
            add("HIGH", "Sensitive data in URL query string",
                "%s  (query: %s)" % (u.split('?')[0], qs[:120]))
        # verbose error disclosure
        rb = r.get("response_body") or ""
        if re.search(r'"(file|line|trace|stack)"\s*:', rb) or "Stack trace" in rb:
            add("MEDIUM", "Verbose error / stack disclosure",
                "%s returns file/line/trace in error body" % u.split('?')[0])
        # security headers (only judge HTML/document responses to avoid noise)
        if (r.get("mime") or "").startswith("text/html"):
            rh = {k.lower(): v for k, v in (r.get("response_headers") or {}).items()}
            missing = [h for h in SECURITY_HEADERS if h not in rh]
            if len(missing) >= 3:
                add("LOW", "Missing security headers",
                    "%s lacks: %s" % (u.split('?')[0], ", ".join(missing)))
            # permissive CORS
            if rh.get("access-control-allow-origin") == "*" and \
               rh.get("access-control-allow-credentials", "").lower() == "true":
                add("HIGH", "CORS: wildcard origin with credentials",
                    "%s" % u.split('?')[0])
        # JWT seen in a (non-masked) body field value
        for mobj in re.finditer(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", rb):
            check_jwt(mobj.group(0), "response of " + u.split('?')[0])
    # sequential/guessable numeric ids across endpoints → IDOR candidate (flag only, never test)
    numeric_ids = []
    for r in recs:
        for mobj in re.finditer(r"\b(?:id|idmovimentacao|iditem|idpedido)\"?\s*[:=]\s*\"?(\d{1,9})\b",
                                (r.get("post_data") or "") + (r.get("response_body") or "")):
            numeric_ids.append(int(mobj.group(1)))
    if len(set(numeric_ids)) >= 3:
        add("LOW", "Sequential numeric IDs present",
            "IDOR candidate — verify access control manually, do NOT enumerate")


def scan_bundle(bundle_dir):
    for f in glob.glob(os.path.join(bundle_dir, "**", "*"), recursive=True):
        if not os.path.isfile(f):
            continue
        try:
            txt = open(f, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for name, pat in SECRET_PATTERNS:
            for mobj in pat.finditer(txt):
                snippet = mobj.group(0)
                sev = "CRITICAL" if name in ("AWS access key", "Stripe secret key",
                                             "Private key block") else "HIGH"
                add(sev, "Possible secret in bundle: %s" % name,
                    "%s  (%s…)" % (os.path.basename(f), snippet[:12]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", required=True)
    ap.add_argument("--bundle")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    scan_capture(args.capture)
    if args.bundle and os.path.isdir(args.bundle):
        scan_bundle(args.bundle)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: order.get(x[0], 9))
    show = findings if args.all else [f for f in findings if f[0] in ("CRITICAL", "HIGH")]

    if not show:
        print("No critical/high passive findings. (%d lower-severity notes; use --all to see.)"
              % len(findings))
    else:
        print("# Passive findings (verify manually, authorized scope only; never exploit)\n")
        for sev, title, detail in show:
            print("[%s] %s\n    %s\n" % (sev, title, detail))

    if any(f[0] == "CRITICAL" for f in findings):
        sys.exit(2)


if __name__ == "__main__":
    main()
