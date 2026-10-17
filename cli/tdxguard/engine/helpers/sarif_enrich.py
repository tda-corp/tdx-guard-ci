#!/usr/bin/env python3
"""
sarif-enrich.py — post-process a SARIF file before pushing it to SecObserve.

    sarif-enrich.py <file.sarif> <repository-directory> [--unescape-html] [--kind-fail]
                    [--rule-roots a,b,c] [--context N] [--expand-context]

It does three things:

1) --unescape-html : unescape the HTML entities in the text fields.
   Trivy 0.58.x renders its SARIF through html/template, so quotes arrive escaped and a
   title reads "&#39;apt-get&#39; missing &#39;--no-install-recommends&#39;".
   SecObserve renders plain text, so the user sees the raw entities. The bug is Trivy's,
   not SecObserve's -> fix it at the source, before it reaches the database.
   Only enable this for Trivy. Semgrep and Gitleaks are not affected.

2) Embed the code with its context into region.snippet.
   Trivy reports line numbers but no code. SecObserve does read region.snippet and puts it
   into the description, so embedding it here shows the code inside the finding instead of
   forcing the reader to open the repository.

   The offending line is marked with a ">" at the front:

        28 |     apt-get update; \\
     >  30 |     apt-get install -y curl; \\

   By default an existing snippet is kept (Opengrep ships a bare one-line one). With
   --expand-context the snippet is rebuilt from the file with --context lines around the
   region and line numbers, so a one-line Opengrep finding still shows its surrounding code
   inline instead of a single stranded line.

3) --rule-roots a,b,c : trim each result.ruleId (and rules[].id) to begin at the first
   path segment matching one of the roots. Opengrep prefixes the rule id with the
   --config path, so a finding's id (which SecObserve shows as its title) becomes
   "ogrules.python.<rule>" or worse; with --rule-roots python,javascript,... it becomes
   the clean "python.<rule>". The scan itself must run from the repo root with a relative
   target so the file paths stay relative and the source links work.

4) --kind-fail : rewrite result.kind "open" -> "fail".
   SARIF reserves kind "fail" for "a problem was found" and "open" for a result that still
   needs human judgement (§3.27.9). SecObserve imports only "fail", which is correct.
   Nuclei, however, stamps "open" on every single match, confirmed ones included, so
   without this every Nuclei finding is dropped and the upload reports 0 observations
   while returning HTTP 200 — a silent loss.
   Only enable this for Nuclei.

Nothing else in the file is touched. Safe to run repeatedly (idempotent).
"""
import html
import json
import sys
from pathlib import Path

MAX_REGION_LINES = 40   # truncate an overly long region so the description stays readable
DEFAULT_CONTEXT = 4     # lines of context above and below


def unescape_deep(node):
    """Unescape the HTML entities in every 'text' field of the SARIF tree."""
    if isinstance(node, dict):
        return {
            k: (html.unescape(v) if k == "text" and isinstance(v, str) else unescape_deep(v))
            for k, v in node.items()
        }
    if isinstance(node, list):
        return [unescape_deep(x) for x in node]
    return node


def build_snippet(path: Path, start: int, end: int, context: int):
    """Build a numbered snippet, marking the offending lines with ">"."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    if not lines or start < 1 or start > len(lines):
        return None

    end = max(end or start, start)
    if end - start + 1 > MAX_REGION_LINES:
        end = start + MAX_REGION_LINES - 1
    lo = max(1, start - context)
    hi = min(len(lines), end + context)

    width = len(str(hi))
    out = []
    for n in range(lo, hi + 1):
        marker = ">" if start <= n <= end else " "
        out.append(f"{marker} {str(n).rjust(width)} | {lines[n - 1]}")
    if hi < len(lines):
        out.append(f"{' ' * (width + 2)} | ...")
    return "\n".join(out)


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    sarif_path, repo = Path(sys.argv[1]), Path(sys.argv[2])
    unescape = "--unescape-html" in sys.argv
    kind_fail = "--kind-fail" in sys.argv
    expand_context = "--expand-context" in sys.argv
    rule_roots = []
    if "--rule-roots" in sys.argv:
        rule_roots = [r for r in sys.argv[sys.argv.index("--rule-roots") + 1].split(",") if r]
    context = DEFAULT_CONTEXT
    if "--context" in sys.argv:
        context = int(sys.argv[sys.argv.index("--context") + 1])

    if not sarif_path.is_file() or sarif_path.stat().st_size == 0:
        return 0
    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"sarif-enrich: skipping {sarif_path.name}: {exc}", file=sys.stderr)
        return 0

    if unescape:
        data = unescape_deep(data)

    def trim_id(rid):
        # Keep the id from the first segment that is a known rule root, dropping the
        # --config path prefix Opengrep prepends. "ogrules.python.sqlalchemy.x" with
        # roots [python,...] -> "python.sqlalchemy.x".
        if not rid or not rule_roots:
            return rid
        parts = rid.split(".")
        for i, seg in enumerate(parts):
            if seg in rule_roots:
                return ".".join(parts[i:])
        return rid

    added = 0
    rekinded = 0
    retitled = 0
    for run in data.get("runs") or []:
        if rule_roots:
            for rule in (run.get("tool", {}).get("driver", {}) or {}).get("rules") or []:
                # SecObserve titles a finding from rule.name (falling back to rule.id), and
                # Opengrep puts the full --config path in rule.name/.id. Trim both, and
                # replace the same ugly string where it is quoted inside the rule's
                # short/full description text ("Opengrep Finding: <full path>").
                for key in ("id", "name"):
                    original = rule.get(key)
                    trimmed = trim_id(original)
                    if trimmed and trimmed != original:
                        rule[key] = trimmed
                        retitled += 1
                        for desc_key in ("shortDescription", "fullDescription"):
                            desc = rule.get(desc_key)
                            if isinstance(desc, dict) and isinstance(desc.get("text"), str):
                                desc["text"] = desc["text"].replace(original, trimmed)
        for result in run.get("results") or []:
            if kind_fail and result.get("kind") == "open":
                result["kind"] = "fail"
                rekinded += 1
            if rule_roots:
                result["ruleId"] = trim_id(result.get("ruleId"))
            for loc in result.get("locations") or []:
                phys = loc.get("physicalLocation") or {}
                uri = (phys.get("artifactLocation") or {}).get("uri")
                region = phys.get("region")
                if not uri or not region:
                    continue
                existing = (region.get("snippet") or {}).get("text")
                # A snippet is already there (Opengrep ships a bare one-line one). By default
                # keep it; with --expand-context, rebuild it from the file with surrounding
                # context and line numbers so the finding is readable inline. If the file can
                # not be read, the scanner's original snippet is left untouched.
                if existing and not expand_context:
                    continue
                start = region.get("startLine")
                if not start:
                    continue
                if uri.startswith("file://"):
                    uri = uri[7:]
                target = repo / uri.lstrip("/")
                snippet = build_snippet(target, start, region.get("endLine"), context)
                if snippet:
                    region["snippet"] = {"text": snippet}
                    added += 1

    sarif_path.write_text(json.dumps(data), encoding="utf-8")
    print(f"sarif-enrich: {sarif_path.name} — embedded {added} snippet(s)"
          + (", unescaped the HTML entities" if unescape else "")
          + (f", rewrote {rekinded} result kind(s) to fail" if kind_fail else "")
          + (f", trimmed {retitled} rule id(s)" if rule_roots else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
