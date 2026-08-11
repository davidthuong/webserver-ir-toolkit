# Contributing

Field corrections are the most valuable contribution here. This toolkit was built during a
real incident on a specific stack; every path and command that came from documentation rather
than a live server is a guess until someone verifies it.

Đóng góp bằng tiếng Việt hoàn toàn được — mở issue hoặc PR bằng tiếng Việt, không cần dịch.

---

## Especially wanted

**Paths and commands for stacks marked untested.** The README lists what has actually been run
in the field. cPanel, CyberPanel, HestiaCP, Virtualmin, nginx and LiteSpeed Enterprise
specifics are implemented from vendor documentation. If you run one of those, a one-line
correction to a log path or config location is worth more than a new feature.

**Webshell samples that evade the current signatures.** Do not attach the malware. Open an
issue with:
- the pattern class (obfuscation technique, not the payload)
- a **minimal synthetic reproduction** — the smallest code that has the property and is not
  itself a working shell
- what the file was named and where it landed

**Clean code that the scanner flags.** False positives are worse than gaps, because a noisy
scanner gets ignored. A snippet of legitimate code that trips a pattern is a bug report.

---

## Rules for the scanner

**`webshell-triage.sh` is read-only and stays that way.** No `rm`, `mv`, `chmod`, `chown`,
`sed -i`, or writes anywhere except the single report file. This is not a style preference:
responders run it on production servers mid-incident, and the guarantee that it cannot make
things worse is why they are willing to.

Cleanup, quarantine and remediation belong in documentation, where a human decides.

**Verify that guarantee rather than trusting it, and re-verify after any change you make.**
`bash tools/verify-readonly.sh` builds a throwaway webroot, snapshots every hash, permission
bit and directory entry, runs the scanner against that tree alone, and diffs.

| Exit | Meaning |
|---|---|
| 0 | pass — the tree came back byte-identical |
| 1 | fail — a file that existed before the scan is gone; the guarantee is broken |
| 2 | inconclusive — the environment interfered, so the run proved nothing either way |

Run it on a server, not a workstation. Endpoint antivirus quarantines the deliberately
malware-shaped files the test creates, and a file your AV removed looks exactly like one the
scanner removed — which is why the script tracks paths that were already unreadable before the
scan started and excludes them from the verdict instead of reporting a false failure.

**Signature changes must be tested both ways.** If you touch the `$SIG` heredoc, verify
against real shell forms *and* against clean code:

```bash
# extract the pattern set
sed -n '/^cat > "\$SIG" <<.PATTERNS.$/,/^PATTERNS$/p' webshell-triage.sh | sed '1d;$d' > /tmp/sig.txt

# then check both directions
printf '%s\n' '<?php eval($compiled_template); ?>' | grep -qEf /tmp/sig.txt && echo "FALSE POSITIVE"
```

State the results in the PR: how many shell forms detected, how many clean samples flagged.
A pattern that adds one detection and two false positives is a regression.

**Portability.** Target `bash` 4.2 and GNU coreutils as shipped on RHEL 7 — that is the oldest
system people are still running this on. No `bash` 5 syntax, no `grep -P`, no GNU-only flags
that BusyBox lacks if you can avoid them.

---

## Documentation

Both languages are maintained: `docs/en/` and `docs/vi/`. A change to one should come with the
matching change to the other. If you only speak one of them, say so in the PR and open an
issue for the other side — a correct document in one language beats a stale document in two.

Write commands out in full rather than describing them. Someone reads these at 2am on a server
that is actively being attacked.

**Say when something is unverified.** "Untested on Plesk 18" is useful. Silent confidence
about a path you have never seen is not.

---

## Reporting security issues in the toolkit itself

If you find something in this repository that could damage a server it runs on — a command
that writes when it should not, a pattern that could be abused, a path traversal in the report
writer — see [SECURITY.md](SECURITY.md).
