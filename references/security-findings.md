# Passive security findings (bug-bounty aid)

This is an **optional, strictly passive** add-on. It triages the data the user
already captured by browsing, to alert them when something serious is visible.
It exists to help legitimate, **authorized** work: bug-bounty programs within
scope, or a pentest the user is permitted to run.

## Hard boundary — do not cross

- **Passive only.** Analyze `recon/live_capture.jsonl` and locally-saved bundle
  files. Send nothing. Never craft, replay, fuzz, or "just try" a request.
- **No exploitation.** Candidates (IDOR, injection points, etc.) are *flagged for
  the human to verify manually within scope* — never tested or enumerated by the
  skill.
- **No evasion / no mass targeting.** No WAF bypass, no scanning many hosts.
- **Scope is the user's responsibility.** Only run this for a target the user is
  authorized to test. If that's unclear, say so and stop at documentation.

If a request would mean actively probing the live site, it's out of scope for
this skill — document the candidate as a gap instead.

## How to run

```
python <skill>/scripts/passive_findings.py --capture recon/live_capture.jsonl --bundle recon/bundle
```

By default it prints only **CRITICAL/HIGH** findings and exits with code `2` if
any CRITICAL exists — so you can "warn only if critical". Add `--all` for the
full list (medium/low notes too).

## What it checks (all from captured data)

- Secrets in the bundle: AWS/Google/Slack/Stripe keys, private-key blocks,
  generic `api_key=/secret=` assignments.
- Tokens / PII / passwords in URL query strings.
- JWT weaknesses: `alg=none`, long lifetime, sensitive claims (ip/email/cpf).
- Verbose error disclosure (file/line/stack in response bodies).
- Permissive CORS (wildcard origin + credentials).
- Missing security headers on HTML responses (CSP/HSTS/X-Frame-Options/nosniff).
- Sequential/guessable numeric IDs → IDOR *candidate* (flag only, never enumerate).

## Reporting

When you run this as part of a recon, only surface CRITICAL/HIGH to the user
proactively ("heads up — found X"). Put the rest in a collapsible "Security
notes" section of the doc. For every item, state it's an unverified candidate to
be checked manually within the authorized program, with the evidence
(`file:line` or the endpoint), and never include a working exploit or an
extraction recipe.
