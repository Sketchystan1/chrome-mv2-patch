"""Sync the embedded fallback tables in both patch scripts from signatures.json.

`signatures.json` is canonical, but each patch script also carries a self-contained
copy so a release needs no external file:

  chrome-mv2.ps1  $EmbeddedSignatures  - JSON, one compact milestone per line,
                                        the `pe` / `pe32` / `pe-arm64` entries
  chrome-mv2.sh   EMBEDDED_SIGNATURES  - pre-tokenized `M|`/`S|`/`E` records (so
                                        the default path needs no python3/JSON),
                                        the `elf`/`elf-arm64` and `macho-*` entries

Forgetting this step ships a patcher that only works when signatures.json happens
to sit beside it. Doing it by hand is worse: an entry can be *modified* or
*removed*, not just added, so an append-only edit leaves a stale duplicate that
the runtime then ties against and declines.

This keys on each entry's header, so it replaces, inserts and deletes in place and
leaves every untouched entry - and the existing order - byte-identical.

    python scripts/sync_embedded.py           # write the tables
    python scripts/sync_embedded.py --check    # report drift, change nothing (CI)
"""

import argparse
import collections
import json
import os
import re
import sys

PE_CONTAINERS = {"pe", "pe32", "pe-arm64"}
SITE_FIELDS = ("name", "kind", "jgRVA", "jgOff", "expectedMatches", "sig")
# Canonical field order for the embedded tables. Only keys actually present on a
# site are emitted, so a plain branch site serializes exactly as before (no drift)
# while a featurebyte / stockOpcode site carries its extra fields.
SITE_FIELD_ORDER = ("name", "kind", "optional", "jgRVA", "jgOff", "stockOpcode",
                    "feature", "structRVA", "patchOff", "stock", "patched",
                    "verify", "expectedMatches", "sig")


def _site_obj(s):
    return {k: s[k] for k in SITE_FIELD_ORDER if k in s}


def ps1_line(entry):
    body = {"name": entry["name"], "container": entry["container"],
            "sites": [_site_obj(s) for s in entry["sites"]]}
    return "    " + json.dumps(body, separators=(",", ":"))


def sh_block(entry):
    out = ["M|%s|%s" % (entry["name"], entry["container"])]
    for site in entry["sites"]:
        if site.get("kind") == "featurebyte":
            # featurebyte is 'pe' only; it never reaches the (ELF/Mach-O) sh table.
            raise SystemExit("sync_embedded: featurebyte site in non-PE milestone %r" % entry["name"])
        # The whole table is one single-quoted shell string, so an apostrophe in a
        # site name would terminate it. Names are documentation only; strip it.
        out.append("S|%s|%s|%s|%d|%d|%s"
                   % (site["name"].replace("'", ""), site["kind"], site["jgRVA"],
                      site["jgOff"], site["expectedMatches"], site["sig"]))
    out.append("E")
    return out


def report(changes, label):
    for kind, name in changes:
        print("  %-8s %-8s %s" % (label, kind, name))


def sync_ps1(path, entries, check):
    src = open(path, encoding="utf-8-sig", newline="").read()
    nl = "\r\n" if "\r\n" in src else "\n"
    head = (r"(\$EmbeddedSignatures = @'" + re.escape(nl) + r"\{" + re.escape(nl)
            + r'  "milestones": \[' + re.escape(nl) + r")")
    tail = r"(" + re.escape(nl) + r"  \]" + re.escape(nl) + r"\}" + re.escape(nl) + r"'@)"
    match = re.search(head + r"((?:.|\n)*?)" + tail, src)
    if not match:
        sys.exit("error: could not find $EmbeddedSignatures in %s" % path)

    changes, kept, seen = [], [], set()
    for line in match.group(2).split("," + nl):
        name = json.loads(line.strip().rstrip(","))["name"]
        if name not in entries:
            changes.append(("removed", name))
            continue
        rebuilt = ps1_line(entries[name])
        if rebuilt != line:
            changes.append(("updated", name))
        kept.append(rebuilt)
        seen.add(name)
    for name, entry in entries.items():
        if entry["container"] in PE_CONTAINERS and name not in seen:
            kept.append(ps1_line(entry))
            changes.append(("added", name))

    report(changes, "ps1")
    if changes and not check:
        open(path, "w", encoding="utf-8", newline="").write(
            src[:match.start(2)] + ("," + nl).join(kept) + src[match.end(2):])
    return changes, len(kept)


def sync_sh(path, entries, check):
    src = open(path, encoding="utf-8", newline="").read()
    nl = "\r\n" if "\r\n" in src else "\n"
    match = re.search(r"(readonly EMBEDDED_SIGNATURES='" + re.escape(nl) + r")((?:.|\n)*?)("
                      + re.escape(nl) + r"'" + re.escape(nl) + r")", src)
    if not match:
        sys.exit("error: could not find EMBEDDED_SIGNATURES in %s" % path)

    lines = match.group(2).split(nl)
    changes, out, seen, i = [], [], set(), 0
    while i < len(lines):
        if not lines[i].startswith("M|"):
            i += 1
            continue
        name = lines[i].split("|")[1]
        end = i
        while end < len(lines) and lines[end] != "E":
            end += 1
        block = lines[i:end + 1]
        if name not in entries:
            changes.append(("removed", name))
        else:
            rebuilt = sh_block(entries[name])
            if rebuilt != block:
                changes.append(("updated", name))
            out.extend(rebuilt)
            seen.add(name)
        i = end + 1
    for name, entry in entries.items():
        if entry["container"] not in PE_CONTAINERS and name not in seen:
            out.extend(sh_block(entry))
            changes.append(("added", name))

    report(changes, "sh")
    if changes and not check:
        open(path, "w", encoding="utf-8", newline="").write(
            src[:match.start(2)] + nl.join(out) + src[match.end(2):])
    return changes, sum(1 for line in out if line.startswith("M|"))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--signatures", default="signatures.json")
    parser.add_argument("--ps1", default="chrome-mv2.ps1")
    parser.add_argument("--sh", default="chrome-mv2.sh")
    parser.add_argument("--check", action="store_true",
                        help="report drift and exit non-zero; do not modify anything")
    args = parser.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for attr in ("signatures", "ps1", "sh"):
        value = getattr(args, attr)
        if not os.path.isabs(value) and not os.path.exists(value):
            setattr(args, attr, os.path.join(root, value))

    with open(args.signatures, encoding="utf-8") as handle:
        table = json.load(handle)
    entries = collections.OrderedDict((m["name"], m) for m in table["milestones"])

    ps1_changes, ps1_count = sync_ps1(args.ps1, entries, args.check)
    sh_changes, sh_count = sync_sh(args.sh, entries, args.check)

    total = len(ps1_changes) + len(sh_changes)
    covered = ps1_count + sh_count
    if covered != len(entries):
        print("error: the two embedded tables hold %d entr(ies) but signatures.json has %d "
              "milestone(s); every milestone belongs to exactly one script, so one has an "
              "unknown container." % (covered, len(entries)), file=sys.stderr)
        return 1
    if not total:
        print("embedded tables already match signatures.json "
              "(ps1 %d, sh %d entries)" % (ps1_count, sh_count))
        return 0
    if args.check:
        print("\n%d embedded entr(ies) drifted from signatures.json - "
              "run scripts/sync_embedded.py" % total)
        return 1
    print("\nsynced %d entr(ies)  (ps1 %d, sh %d)" % (total, ps1_count, sh_count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
