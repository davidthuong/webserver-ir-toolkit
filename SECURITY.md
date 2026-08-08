# Security Policy

## Reporting an issue in this toolkit

Open a [private security advisory][advisory] rather than a public issue if the problem could
damage a server that runs this code — for example a command that writes when
it should only read, an unquoted expansion that could be exploited through a crafted filename,
or anything in the report writer that could be redirected outside the intended path.

For everything else, a normal issue is fine.

[advisory]: https://github.com/davidthuong/webserver-ir-toolkit/security/advisories/new

Báo lỗi bằng tiếng Việt được, không cần dịch.

---

## Do not send malware

Please do not attach webshells, packed samples or live payloads to issues, pull requests or
email. If a signature gap needs demonstrating, send a **minimal synthetic reproduction** — the
smallest snippet that exhibits the property, which is not itself a functioning shell.

If a real sample is genuinely necessary to fix something, say so in the issue and we will
arrange it out of band. Do not upload it first.

---

## Scope

This repository contains **defensive tooling**: a read-only scanner and response
documentation. It is intended for administrators examining servers they are responsible for.

Out of scope, and will be closed without discussion:

- Requests to add exploitation, mass-scanning, or "test if other servers are vulnerable"
  functionality
- Requests to add automated deletion or quarantine to `webshell-triage.sh` — see
  [CONTRIBUTING.md](CONTRIBUTING.md) for why the read-only guarantee is load-bearing
- Requests for help attacking a system, or for the working shells that some documentation here
  describes generically

---

## A note on the CVEs referenced

Documentation in this repository cites specific vulnerabilities as worked examples of how to
trace an entry point. Those references describe **where to look in your own logs and which
version to upgrade to**. They deliberately do not include working exploit code, and pull
requests adding it will be rejected.

Vulnerability details are cited from vendor advisories and public databases. Verify the current
affected-version range against the vendor before acting — advisories get amended, and a version
listed as safe here may not stay that way.
