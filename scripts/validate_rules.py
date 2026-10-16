"""
Cyberion ThreatShield | scripts/validate_rules.py
=================================================
Sigma Rule Validation & Telemetry Harness

Loads all .yml Sigma rules from rules/**/,
validates required PRD Section 8 fields,
evaluates detection logic against the 3 JSON datasets,
and prints a rich terminal summary table.

Usage:
    python scripts/validate_rules.py
    python scripts/validate_rules.py --json-report results/validation_report.json
    python scripts/validate_rules.py --rules-dir rules --datasets-dir datasets
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent.parent
RULES_DIR = BASE_DIR / "rules"
DATASETS_DIR = BASE_DIR / "datasets"

REQUIRED_FIELDS = [
    "title", "id", "status", "description",
    "references", "tags", "logsource", "detection",
    "falsepositives", "level",
]

VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
VALID_LEVELS = {"critical", "high", "medium", "low", "informational"}

DATASET_FILES = {
    "windows_security_sysmon": "windows_security_sysmon_sample.json",
    "zeek_network": "zeek_network_sample.json",
    "linux_auth_auditd": "linux_auth_auditd_sample.json",
}

console = Console()


# ===========================================================================
# Sigma Detection Evaluator
# ===========================================================================

class SigmaEvaluator:
    """
    Minimal Sigma detection evaluator supporting:
      - selection / filter named groups
      - condition expressions (1 of them*, all of them, named references)
      - field modifiers: |contains, |endswith, |startswith, |all, |re
      - count/timeframe correlation stubs
    """

    def __init__(self, detection: dict[str, Any]):
        self.detection = detection
        self.condition_str: str = str(detection.get("condition", "selection"))

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def evaluate(self, records: list[dict]) -> int:
        """Return count of records matching the detection condition."""
        matched = 0
        for record in records:
            try:
                if self._eval_condition(record):
                    matched += 1
            except Exception:
                pass
        return matched

    # ------------------------------------------------------------------
    # Condition parsing
    # ------------------------------------------------------------------
    def _eval_condition(self, record: dict) -> bool:
        cond = self.condition_str.strip()

        # Correlation rules: "selection | count(...) > N" or "selection_fail | count() by ... > 5"
        m_pipe = re.search(r"(\w+)\s*\|\s*count\b", cond, re.I)
        if m_pipe:
            group_name = m_pipe.group(1)
            return self._eval_named_or_wildcard(group_name, record)

        # count(<named>) by <field> over <timeframe> | threshold <N>
        # Correlation rules: evaluate the underlying selection per-record.
        # A record that matches the selection is a candidate event.
        # We report total candidate events; the harness counts them.
        m_count = re.match(r"^\s*count\s*\(\s*(\w+)\s*\)", cond, re.I)
        if m_count:
            group_name = m_count.group(1)
            return self._eval_named_or_wildcard(group_name, record)

        # "count() ..." without a named group — fall back to selection
        if re.match(r"^\s*count\s*\(", cond, re.I):
            return self._eval_named_or_wildcard("selection", record)

        # "1 of <filter*>" – any named group matching wildcard
        m = re.match(r"^1\s+of\s+([\w]+\*?)\s*$", cond, re.I)
        if m:
            return self._eval_one_of(m.group(1), record)

        # "all of <filter*>"
        m = re.match(r"^all\s+of\s+([\w]+\*?)\s*$", cond, re.I)
        if m:
            return self._eval_all_of(m.group(1), record)

        # Compound: "selection and not filter"
        return self._eval_compound(cond, record)

    def _eval_compound(self, cond: str, record: dict) -> bool:
        """Evaluate compound boolean expressions left-to-right."""
        # Tokenise respecting parentheses (simple approach)
        tokens = re.split(r"\b(and|or|not)\b", cond, flags=re.I)
        result = None
        op = "or"  # initial implicit

        for token in tokens:
            token = token.strip()
            if not token:
                continue
            token_lower = token.lower()
            if token_lower in ("and", "or", "not"):
                op = token_lower
                continue

            # Strip parens
            token = token.strip("() ")
            if not token:
                continue

            # Check if token is "1 of <pattern>" or "all of <pattern>"
            m_one = re.match(r"^1\s+of\s+([\w*]+)\s*$", token, re.I)
            m_all = re.match(r"^all\s+of\s+([\w*]+)\s*$", token, re.I)
            if m_one:
                val = self._eval_one_of(m_one.group(1), record)
            elif m_all:
                val = self._eval_all_of(m_all.group(1), record)
            else:
                val = self._eval_named_or_wildcard(token, record)

            if op == "not":
                val = not val
                op = "and"  # not binds to the next term, then implicit AND
            if result is None:
                result = val
            elif op == "and":
                result = result and val
            else:  # or
                result = result or val

        return bool(result)

    # ------------------------------------------------------------------
    # Group resolution
    # ------------------------------------------------------------------
    def _eval_one_of(self, pattern: str, record: dict) -> bool:
        groups = self._resolve_pattern(pattern)
        return any(self._eval_group(g, record) for g in groups)

    def _eval_all_of(self, pattern: str, record: dict) -> bool:
        groups = self._resolve_pattern(pattern)
        if not groups:
            return False
        return all(self._eval_group(g, record) for g in groups)

    def _eval_named_or_wildcard(self, name: str, record: dict) -> bool:
        if name.endswith("*"):
            return self._eval_one_of(name, record)
        return self._eval_group(name, record)

    def _resolve_pattern(self, pattern: str) -> list[str]:
        """Expand wildcard group names (e.g. 'filter*' → all keys starting with filter)."""
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return [k for k in self.detection if k != "condition" and k.startswith(prefix)]
        if pattern == "them":
            return [k for k in self.detection if k != "condition"]
        return [pattern] if pattern in self.detection else []

    # ------------------------------------------------------------------
    # Group evaluation
    # ------------------------------------------------------------------
    def _eval_group(self, group_name: str, record: dict) -> bool:
        group = self.detection.get(group_name)
        if group is None:
            return False

        # List of maps → OR between items, AND within each item
        if isinstance(group, list):
            for item in group:
                if isinstance(item, dict):
                    if self._match_map(item, record):
                        return True
                else:
                    # bare scalar in list – check any field
                    if self._scalar_in_record(item, record):
                        return True
            return False

        # Single map → AND between all key/value pairs
        if isinstance(group, dict):
            return self._match_map(group, record)

        # Bare scalar
        return self._scalar_in_record(group, record)

    # ------------------------------------------------------------------
    # Field-level matching with modifier support
    # ------------------------------------------------------------------
    def _match_map(self, mapping: dict, record: dict) -> bool:
        """All keys in mapping must match (AND logic)."""
        for raw_key, criteria in mapping.items():
            if not self._match_field(raw_key, criteria, record):
                return False
        return True

    def _match_field(self, raw_key: str, criteria: Any, record: dict) -> bool:
        parts = raw_key.split("|")
        field_name = parts[0]
        modifiers = [m.lower() for m in parts[1:]]

        field_value = self._get_field(field_name, record)

        # Normalise criteria to a list for uniform handling
        if not isinstance(criteria, list):
            criteria = [criteria]

        # "|all" – every criterion must match
        all_mode = "all" in modifiers

        results = [self._apply_modifiers(field_value, str(c), modifiers) for c in criteria]
        return all(results) if all_mode else any(results)

    def _apply_modifiers(self, field_value: Any, criterion: str, modifiers: list[str]) -> bool:
        if field_value is None:
            return False

        # Numeric comparisons: |gt, |lt, |gte, |lte
        if any(m in modifiers for m in ("gt", "lt", "gte", "lte")):
            try:
                fv_num = float(field_value)
                cv_num = float(criterion)
                if "gte" in modifiers:
                    return fv_num >= cv_num
                if "lte" in modifiers:
                    return fv_num <= cv_num
                if "gt" in modifiers:
                    return fv_num > cv_num
                if "lt" in modifiers:
                    return fv_num < cv_num
            except (ValueError, TypeError):
                return False

        fv = str(field_value).lower()
        cv = criterion.lower()

        if "re" in modifiers:
            try:
                return bool(re.search(cv, fv, re.I))
            except re.error:
                return False
        if "contains" in modifiers:
            return cv in fv
        if "startswith" in modifiers:
            return fv.startswith(cv)
        if "endswith" in modifiers:
            return fv.endswith(cv)
        # Default: exact match — also supports integer EventID matching
        # Try numeric equality first when criterion is a pure integer/float
        try:
            if cv == str(int(float(cv))):
                return float(field_value) == float(cv)
        except (ValueError, TypeError):
            pass
        return fv == cv

    def _get_field(self, field_name: str, record: dict) -> Any:
        """Retrieve field value supporting dotted notation and common Sigma aliases."""
        # Direct key
        if field_name in record:
            return record[field_name]
        # Case-insensitive search
        for k, v in record.items():
            if k.lower() == field_name.lower():
                return v
        # Dotted path (e.g. "id.orig_h")
        parts = field_name.split(".")
        node = record
        for p in parts:
            if isinstance(node, dict):
                node = node.get(p)
            else:
                return None
        return node

    def _scalar_in_record(self, scalar: Any, record: dict) -> bool:
        s = str(scalar).lower()
        return any(s in str(v).lower() for v in record.values() if v is not None)


# ===========================================================================
# Dataset loader
# ===========================================================================

def load_datasets(datasets_dir: Path) -> dict[str, list[dict]]:
    datasets: dict[str, list[dict]] = {}
    for label, filename in DATASET_FILES.items():
        path = datasets_dir / filename
        if not path.exists():
            console.print(f"[yellow]  [WARN] Dataset not found: {path}[/yellow]")
            datasets[label] = []
            continue
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            datasets[label] = data
        else:
            datasets[label] = [data]
        console.print(f"[green]  [OK]   Loaded {label}: {len(datasets[label])} records[/green]")
    return datasets


# ===========================================================================
# Rule loader & validator
# ===========================================================================

def discover_rules(rules_dir: Path) -> list[Path]:
    return sorted(rules_dir.rglob("*.yml"))


def validate_rule_fields(rule: dict, path: Path) -> list[str]:
    """Return list of validation error messages."""
    errors: list[str] = []

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: '{field}'")

    # Validate status
    status = rule.get("status", "")
    if status and str(status) not in VALID_STATUSES:
        errors.append(f"Invalid status '{status}'. Must be one of: {VALID_STATUSES}")

    # Validate level
    level = rule.get("level", "")
    if level and str(level) not in VALID_LEVELS:
        errors.append(f"Invalid level '{level}'. Must be one of: {VALID_LEVELS}")

    # Validate tags contain at least one attack.tXXXX (including sub-techniques like t1003.001)
    tags = rule.get("tags", [])
    if isinstance(tags, list):
        attack_tags = [t for t in tags if re.match(r"attack\.t\d{4}(\.\d+)?", str(t), re.I)]
        if not attack_tags:
            errors.append("tags must contain at least one 'attack.tXXXX' technique tag")
    else:
        errors.append("tags must be a list")

    # Validate references is a list
    refs = rule.get("references", [])
    if not isinstance(refs, list):
        errors.append("references must be a list")

    # Validate detection block has a condition
    detection = rule.get("detection", {})
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("detection block is missing 'condition' key")
    else:
        errors.append("detection must be a dict")

    # Validate UUID id field
    rule_id = rule.get("id", "")
    if rule_id:
        try:
            uuid.UUID(str(rule_id))
        except ValueError:
            errors.append(f"id '{rule_id}' is not a valid UUID")

    return errors


def extract_mitre_techniques(tags: list) -> str:
    techniques = [t.upper().replace("ATTACK.", "") for t in tags
                  if re.match(r"attack\.t\d{4}", str(t), re.I)]
    return ", ".join(techniques) if techniques else "N/A"


def map_logsource_to_dataset(logsource: dict) -> str:
    """Map Sigma logsource block to our dataset label."""
    product = str(logsource.get("product", "")).lower()
    category = str(logsource.get("category", "")).lower()
    service = str(logsource.get("service", "")).lower()
    definition = str(logsource.get("definition", "")).lower()

    if "windows" in product:
        return "windows_security_sysmon"
    if "linux" in product or "unix" in product:
        return "linux_auth_auditd"
    if "zeek" in product or "zeek" in category or "zeek" in service or "zeek" in definition:
        return "zeek_network"
    if "network" in product and "windows" not in product:
        return "zeek_network"
    if "sysmon" in service or "security" in service:
        return "windows_security_sysmon"
    if "auditd" in service or "auth" in service:
        return "linux_auth_auditd"

    # Fallback: try all
    return "all"


# ===========================================================================
# Main validation runner
# ===========================================================================

def run_validation(rules_dir: Path, datasets_dir: Path) -> list[dict]:
    """
    Validate all rules and return a list of result dicts.
    Works cleanly even with 0 rules.
    """
    datasets = load_datasets(datasets_dir)
    rule_paths = discover_rules(rules_dir)

    console.print(f"\n[bold cyan]  Rules discovered: {len(rule_paths)}[/bold cyan]")

    results = []

    for rule_path in rule_paths:
        # --- Load YAML ---
        try:
            with open(rule_path, encoding="utf-8") as fh:
                rule = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            results.append({
                "rule_id": str(rule_path.name),
                "title": rule_path.stem,
                "mitre_technique": "N/A",
                "level": "N/A",
                "dataset": "N/A",
                "matched_events": 0,
                "status": "FAIL",
                "errors": [f"YAML parse error: {exc}"],
                "path": str(rule_path),
            })
            continue

        if not isinstance(rule, dict):
            results.append({
                "rule_id": str(rule_path.name),
                "title": rule_path.stem,
                "mitre_technique": "N/A",
                "level": "N/A",
                "dataset": "N/A",
                "matched_events": 0,
                "status": "FAIL",
                "errors": ["Rule is not a valid YAML dict"],
                "path": str(rule_path),
            })
            continue

        # --- Field validation ---
        field_errors = validate_rule_fields(rule, rule_path)

        rule_id = str(rule.get("id", rule_path.stem))
        title = str(rule.get("title", rule_path.stem))
        level = str(rule.get("level", "N/A"))
        tags = rule.get("tags", [])
        mitre = extract_mitre_techniques(tags if isinstance(tags, list) else [])
        logsource = rule.get("logsource", {})
        detection = rule.get("detection", {})

        # --- Dataset selection ---
        dataset_label = map_logsource_to_dataset(logsource if isinstance(logsource, dict) else {})

        # --- Detection evaluation ---
        matched_total = 0
        datasets_tested: list[str] = []

        if not field_errors and isinstance(detection, dict):
            evaluator = SigmaEvaluator(detection)
            if dataset_label == "all":
                for label, records in datasets.items():
                    count = evaluator.evaluate(records)
                    matched_total += count
                    datasets_tested.append(f"{label}({count})")
            else:
                records = datasets.get(dataset_label, [])
                matched_total = evaluator.evaluate(records)
                datasets_tested.append(f"{dataset_label}({matched_total})")

        status = "FAIL" if field_errors else "PASS"

        results.append({
            "rule_id": rule_id,
            "title": title,
            "mitre_technique": mitre,
            "level": level,
            "dataset": dataset_label if not datasets_tested else "; ".join(datasets_tested),
            "matched_events": matched_total,
            "status": status,
            "errors": field_errors,
            "path": str(rule_path),
        })

    return results


# ===========================================================================
# Rich output rendering
# ===========================================================================

LEVEL_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "green",
}

STATUS_COLORS = {
    "PASS": "bold green",
    "FAIL": "bold red",
}


def render_table(results: list[dict]) -> None:
    table = Table(
        title="[bold]Cyberion ThreatShield | Sigma Rule Validation Report[/bold]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold magenta",
        border_style="bright_blue",
        expand=True,
    )

    table.add_column("#",         style="dim",         width=3,  justify="right")
    table.add_column("Rule ID",   style="dim cyan",    width=38, overflow="fold")
    table.add_column("Title",     style="bold white",  width=30, overflow="fold")
    table.add_column("Technique", style="bold yellow", width=18, overflow="fold")
    table.add_column("Severity",  width=12, justify="center")
    table.add_column("Dataset",   width=22, overflow="fold")
    table.add_column("Matches",   width=8,  justify="center")
    table.add_column("Status",    width=8,  justify="center")

    for i, r in enumerate(results, 1):
        level_color = LEVEL_COLORS.get(r["level"].lower(), "white")
        status_color = STATUS_COLORS.get(r["status"], "white")

        # Truncate dataset label for display
        dataset_disp = r["dataset"]
        if len(dataset_disp) > 22:
            dataset_disp = dataset_disp[:19] + "..."

        table.add_row(
            str(i),
            r["rule_id"],
            r["title"],
            r["mitre_technique"],
            f"[{level_color}]{r['level']}[/{level_color}]",
            dataset_disp,
            str(r["matched_events"]) if r["matched_events"] >= 0 else "N/A",
            f"[{status_color}]{r['status']}[/{status_color}]",
        )

    console.print()
    console.print(table)

    # Print errors for FAIL rules
    for r in results:
        if r["errors"]:
            console.print(f"\n[bold red][ERRORS] {r['title']} ({r['rule_id']})[/bold red]")
            for err in r["errors"]:
                console.print(f"  [red]• {err}[/red]")


def render_summary(results: list[dict], datasets: dict, rules_dir: Path) -> None:
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = total - passed
    total_matches = sum(r["matched_events"] for r in results)

    dataset_summary = ", ".join(
        f"{k}: {len(v)} records" for k, v in datasets.items()
    )

    panel_text = (
        f"[bold]Engagement:[/bold] Cyberion ThreatShield (PROJ-CYBE-260802 / CDL-DET-V2)\n"
        f"[bold]Timestamp:[/bold] {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"[bold]Rules Dir:[/bold] {rules_dir}\n"
        f"[bold]Datasets:[/bold] {dataset_summary}\n\n"
        f"[bold]Total Rules:[/bold]   {total}\n"
        f"[bold green]  PASS:[/bold green]         {passed}\n"
        f"[bold red]  FAIL:[/bold red]         {failed}\n"
        f"[bold]Total Matches:[/bold] {total_matches}"
    )

    if total == 0:
        panel_text += (
            "\n\n[dim italic]No rules found in rules/ subdirectories.\n"
            "Add .yml Sigma rules to begin detection validation.[/dim italic]"
        )

    console.print(Panel(panel_text, title="[bold cyan]Validation Summary[/bold cyan]",
                        border_style="cyan", expand=False))


# ===========================================================================
# CLI entry point
# ===========================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cyberion ThreatShield: Sigma Rule Validation & Telemetry Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/validate_rules.py
  python scripts/validate_rules.py --json-report results/report.json
  python scripts/validate_rules.py --rules-dir rules --datasets-dir datasets
""",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=RULES_DIR,
        help="Directory containing Sigma .yml rule files (default: rules/)",
    )
    parser.add_argument(
        "--datasets-dir",
        type=Path,
        default=DATASETS_DIR,
        help="Directory containing telemetry JSON datasets (default: datasets/)",
    )
    parser.add_argument(
        "--json-report",
        type=Path,
        default=None,
        help="Path to export validation results as JSON (optional)",
    )
    parser.add_argument(
        "--fail-on-errors",
        action="store_true",
        default=False,
        help="Exit with code 1 if any rule fails validation",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    console.print(Panel(
        "[bold cyan]Cyberion ThreatShield[/bold cyan] | Sigma Rule Validation & Telemetry Harness\n"
        "[dim]Detection Engineering & Threat Hunting Platform — Phase 1 (PROJ-CYBE-260802)[/dim]",
        border_style="bright_blue",
        expand=False,
    ))

    # Validate paths
    if not args.rules_dir.exists():
        console.print(f"[red][ERROR] Rules directory not found: {args.rules_dir}[/red]")
        sys.exit(1)
    if not args.datasets_dir.exists():
        console.print(f"[red][ERROR] Datasets directory not found: {args.datasets_dir}[/red]")
        sys.exit(1)

    console.print(f"\n[bold]Loading datasets from:[/bold] {args.datasets_dir}")
    datasets = load_datasets(args.datasets_dir)

    console.print(f"\n[bold]Scanning rules from:[/bold] {args.rules_dir}")
    results = run_validation(args.rules_dir, args.datasets_dir)

    # Render output
    render_summary(results, datasets, args.rules_dir)
    if results:
        render_table(results)

    # JSON report export
    if args.json_report:
        args.json_report.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "meta": {
                "engagement": "Cyberion ThreatShield (PROJ-CYBE-260802 / CDL-DET-V2)",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "rules_dir": str(args.rules_dir),
                "datasets_dir": str(args.datasets_dir),
                "total_rules": len(results),
                "passed": sum(1 for r in results if r["status"] == "PASS"),
                "failed": sum(1 for r in results if r["status"] == "FAIL"),
                "total_matches": sum(r["matched_events"] for r in results),
            },
            "dataset_stats": {
                label: {"path": str(args.datasets_dir / fname), "records": len(datasets.get(label, []))}
                for label, fname in DATASET_FILES.items()
            },
            "results": results,
        }
        with open(args.json_report, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        console.print(f"\n[green][+] JSON report written to: {args.json_report}[/green]")

    # Exit code
    if args.fail_on_errors and any(r["status"] == "FAIL" for r in results):
        sys.exit(1)

    console.print("\n[bold green][*] Validation complete.[/bold green]\n")


if __name__ == "__main__":
    main()
