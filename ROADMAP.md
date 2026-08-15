# Roadmap

Where this project is, what is verified, and what is planned.

🇻🇳 **[Bản tiếng Việt](docs/vi/ROADMAP.md)**

Everything here was built during real incident response on shared hosting, and the
distinction that matters most in this document is between **what has been exercised on a
compromised production host** and **what was implemented from vendor documentation**. Both
ship; only one has been proven.

---

## Where it stands

The scanner runs 20 sections and is read-only by construction, which
[tools/verify-readonly.sh](tools/verify-readonly.sh) demonstrates rather than asserts.
Documentation is maintained in English and Vietnamese with parity.

### Detection, and how it was measured

| Layer | Result | Method |
|---|---|---|
| Webshell signatures | 16/16 detected, 0/12 false positives | 16 real shell forms against 12 clean-code controls chosen to be the constructs naive patterns trip on |
| Anti-cleanup + client-side injection | 5/5 detected, 0/7 false positives | Samples recovered from a live compromise, including a repeating-key XOR loader |
| Generic detection thresholds | separates cleanly | Measured: a malicious payload carried a 56,030-char base64 run against 1,467 for a legitimately embedded icon |
| Read-only guarantee | PASS | Full 20-section run over a fixture tree; sha256, permissions and directory listing identical before and after |

### Platform coverage

| Stack | Status |
|---|---|
| CentOS 7 / RHEL family | **Verified in the field** |
| DirectAdmin | **Verified in the field** |
| OpenLiteSpeed | **Verified in the field** — including that `.htaccess` is silently ignored |
| ProFTPD | **Verified in the field** |
| Imunify360 | **Verified in the field** |
| Apache | Partially — paths and `AllowOverride` handling implemented, not run on a compromised Apache host |
| Plesk | From documentation |
| cPanel | From documentation |
| nginx | From documentation |
| LiteSpeed Enterprise | From documentation — the edition split matters and the script refuses to guess it |
| CyberPanel, Virtualmin | Log paths only |
| Debian / Ubuntu | From documentation |

Two features have never been exercised against a real compromise: `--http` (black-box fetch
and cloaking diff) and `--checksums` (WordPress package verification). The second is,
structurally, the strongest check in the toolkit, because it asks whether files match what
upstream shipped rather than whether they resemble something previously described.

---

## Next

Ordered by how much each reduces the chance of a report being quietly wrong.

**A signature test runner.** `CONTRIBUTING.md` asks contributors to re-test the pattern set in
both directions, and then offers no way to do it. The corpus that produced the 16/16 and 0/12
figures exists only as ad-hoc commands. A `tools/test-signatures.sh` with checked-in synthetic
fixtures would make that instruction executable and make pattern contributions safe to accept.
This ranks first because every defect found in this toolkit so far was found by testing, and
two of them were pattern bugs that failed silently.

**Joomla integrity verification.** WordPress has `wp core verify-checksums` and
`wp plugin verify-checksums`, and they are the only checks that reliably find a family nobody
has described. Joomla ships no equivalent, and the current guidance — diff against a clean
archive of the same version — is a manual procedure rather than a check. Joomla installations
were the majority of compromised sites in the incident this toolkit came from.

**CMS and extension inventory.** Producing a version list across every account on a host is
mechanical and is the input to every "is this vulnerable" question. Vulnerability data itself
stays out of scope, see non-goals.

**Machine-readable output.** A `--json` mode so findings can feed a ticketing system or be
diffed between runs. The report is currently for human reading only.

**Baseline and drift tooling.** `PLAYBOOK.md` Phase 8 documents taking a hash baseline after
remediation and comparing daily; it is prose, not a script. Baseline comparison is the only
detection method that does not depend on recognising the malware, so it deserves to be a tool.

**Bilingual glossary.** `containment` and `mitigation` are currently translated
interchangeably in places. A term list would keep the two language trees from drifting as
contributors arrive.

---

## Later

**Remediation tooling with backup and rollback**, kept strictly separate from the scanner and
never invoked by it. The scanner's read-only guarantee is why responders are willing to run it
mid-incident, and that guarantee is not negotiable. Any cleanup tool would take an explicit,
human-reviewed file list as input.

**Field corrections for the stacks listed as unverified.** This is not something the
maintainers can manufacture; it needs people who run those stacks. A one-line correction to a
log path is worth more than a feature.

---

## Non-goals

**No exploitation, scanning of hosts you do not administer, or "check if others are
vulnerable" functionality.** This is defensive tooling for examining your own servers.

**No automated deletion or quarantine in the scanner.** See above; the read-only property is
load-bearing.

**No vulnerability database.** Advisories are cited as worked examples of tracing an entry
point, with a pointer to the vendor for the current affected range. Maintaining version data
here would produce a stale database that people trust.

**Not a replacement for a commercial scanner.** The strength of this toolkit is the
persistence surface and entry-point attribution that Imunify360, maldet and ClamAV do not
cover. Run it alongside one, not instead of one.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most useful contributions, in order: corrections
for stacks marked unverified above, clean code that the scanner falsely flags, and evasion
techniques the patterns miss — described as a minimal synthetic reproduction, never as an
attached sample.
