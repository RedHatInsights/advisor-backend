#!/usr/bin/env python3
"""
Mutmut Execution Runner for Fast PR Verification
with GitHub Actions Step Summary Generation.
"""
import ast
import os
import re
import subprocess
import sys
from pathlib import Path

from mutmut.mutation.data import SourceFileMutationData
from mutmut.mutation.diff_apply import get_diff_for_mutant
from mutmut.stats import status_by_exit_code

def _get_git_diff_output(base_branch: str) -> str:
    """Retrieves unified diff output with zero context lines."""
    if not re.match(r"^[a-zA-Z0-9_\-./]+$", base_branch):
        raise ValueError(f"Invalid git base branch or reference: {base_branch!r}")

    result = subprocess.run(
        ["git", "diff", "-U0", "--diff-filter=d", f"{base_branch}...HEAD", "--"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        result = subprocess.run(
            ["git", "diff", "-U0", "--diff-filter=d", "HEAD", "--"],
            capture_output=True,
            text=True,
            check=True,
        )
    return result.stdout


HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _extract_hunk_range(line: str) -> range | None:
    match = HUNK_PATTERN.match(line)
    if not match:
        return None
    start = int(match.group(1))
    count = int(match.group(2)) if match.group(2) is not None else 1
    return range(start, start + count)


def _parse_diff_lines(diff_output: str) -> dict[str, set[int]]:
    """Parses unified diff output to map modified line numbers per file."""
    changed_lines: dict[str, set[int]] = {}
    current_file = None

    for line in diff_output.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            if current_file.endswith(".py"):
                changed_lines.setdefault(current_file, set())
        elif line.startswith("@@") and current_file and current_file.endswith(".py"):
            line_range = _extract_hunk_range(line)
            if line_range:
                changed_lines[current_file].update(line_range)
    return changed_lines


def get_changed_lines_by_file(base_branch: str = "origin/master") -> dict[str, set[int]]:
    """Extracts exact modified line numbers per python file vs base branch."""
    diff_output = _get_git_diff_output(base_branch)
    return _parse_diff_lines(diff_output)


def filter_target_files(changed_lines: dict[str, set[int]]) -> dict[str, set[int]]:
    """Filters out non-business code (migrations, tests, admin, settings)."""
    targets = {}
    ignored_patterns = ["migrations/", "tests/", "test_", "admin.py", "project_settings/"]
    allowed_prefixes = ("api/advisor/api/", "api/advisor/tasks/", "api/advisor/sat_compat/", "service/")

    for file_path, lines in changed_lines.items():
        if any(pat in file_path for pat in ignored_patterns):
            continue
        if file_path.startswith(allowed_prefixes) and Path(file_path).exists():
            targets[file_path] = lines
    return targets


def parse_function_and_class_from_mutant_name(mutant_key: str) -> tuple[str, str | None]:
    """
    Extracts original function name and optional class name from mutmut key.
    Examples:
      - 'api.advisor.api.filters.x_filter_by_staleness__mutmut_1' -> ('filter_by_staleness', None)
      - 'service.service.xǁMyClassǁmy_method__mutmut_2' -> ('my_method', 'MyClass')
    """
    base_name = mutant_key.split("__mutmut_")[0]
    func_identifier = base_name.split(".")[-1]

    if "ǁ" in func_identifier:
        parts = func_identifier.split("ǁ")
        class_name = parts[1]
        func_name = parts[2]
        return func_name, class_name
    elif func_identifier.startswith("x_"):
        return func_identifier[2:], None
    return func_identifier, None


def get_function_start_line(file_path: str, func_name: str, class_name: str | None = None) -> int:
    """Finds the absolute starting line of a function/method in a file using Python AST."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=file_path)

        for node in ast.walk(tree):
            if class_name and isinstance(node, ast.ClassDef) and node.name == class_name:
                for subnode in node.body:
                    if isinstance(subnode, (ast.FunctionDef, ast.AsyncFunctionDef)) and subnode.name == func_name:
                        return subnode.lineno
            elif not class_name and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                return node.lineno
    except (OSError, SyntaxError, UnicodeDecodeError):
        pass
    return 1


def parse_mutant_relative_line(diff_text: str) -> int:
    """
    Extracts the relative 1-based line number of the first mutated line
    within the isolated function diff by walking context lines.
    """
    current_line = 1
    in_hunk = False

    for line in diff_text.splitlines():
        if line.startswith("@@"):
            match = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
            current_line = int(match.group(1)) if match else 1
            in_hunk = True
        elif in_hunk:
            if (line.startswith("+") and not line.startswith("+++")) or (
                line.startswith("-") and not line.startswith("---")
            ):
                return current_line
            elif line.startswith(" "):
                current_line += 1

    return 1


def _collect_survivor_info(targets: dict[str, set[int]]) -> tuple[list[dict], list[dict]]:
    """Reads Mutmut results and diffs in-memory and partitions survivors into PR vs Legacy."""
    pr_survivors = []
    legacy_survivors = []

    for file_path, changed_lines in targets.items():
        mutation_data = SourceFileMutationData(path=file_path)
        mutation_data.load()

        for mutant_name, exit_code in mutation_data.exit_code_by_key.items():
            status = status_by_exit_code.get(exit_code, "")
            if status not in ("survived", "suspicious", "bad_survived"):
                continue

            try:
                diff_text = get_diff_for_mutant(mutant_name, path=file_path)
            except Exception:
                diff_text = f"Unable to generate diff for mutant {mutant_name}"

            rel_line = parse_mutant_relative_line(diff_text)
            func_name, class_name = parse_function_and_class_from_mutant_name(mutant_name)
            func_start = get_function_start_line(file_path, func_name, class_name)
            actual_line = func_start + rel_line - 1

            mutant_info = {
                "name": mutant_name,
                "file": file_path,
                "line": actual_line,
                "diff": diff_text,
            }

            if actual_line in changed_lines:
                pr_survivors.append(mutant_info)
            else:
                legacy_survivors.append(mutant_info)

    return pr_survivors, legacy_survivors


def write_github_summary(pr_survivors: list[dict], legacy_survivors: list[dict], targets: dict) -> None:
    """Writes a report to $GITHUB_STEP_SUMMARY ONLY when there are actionable PR survivors."""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path or not pr_survivors:
        return

    with open(summary_path, "a", encoding="utf-8") as f:
        f.write("## 🧬 Mutation Testing Alert (Action Required)\n\n")
        f.write(f"⚠️ **{len(pr_survivors)} surviving mutant(s)** detected in code modified in this PR.\n\n")
        f.write("| Metric | Value |\n")
        f.write("| :--- | :---: |\n")
        f.write(f"| **Modified Files Checked** | `{len(targets)}` |\n")
        f.write(f"| **PR Surviving Mutants (New Code)** | `{len(pr_survivors)}` |\n")
        f.write(f"| **Legacy Surviving Mutants (Ignored)** | `{len(legacy_survivors)}` |\n\n")
        f.write("### ⚠️ Surviving Mutants in Modified Lines\n")
        f.write("> Add test assertions to cover these specific modified paths:\n\n")

        for item in pr_survivors:
            f.write(f"<details open><summary><b>{item['file']} (Line ~{item.get('line', '?')}) — Mutant <code>{item['name']}</code></b></summary>\n\n")
            f.write("```diff\n")
            f.write(item["diff"])
            f.write("\n```\n</details>\n\n")


def run_mutation_on_targets(targets: dict[str, set[int]]) -> int:
    if not targets:
        print("✅ No modified business logic files to mutate.")
        return 0

    print(f"🎯 Target files for mutation testing ({len(targets)}):")
    for file_path, lines in targets.items():
        print(f"  - {file_path} (Modified lines: {sorted(lines)})")

    for file_path in targets:
        print(f"\n🚀 Running Mutmut on: {file_path}")
        run_res = subprocess.run([sys.executable, "-m", "mutmut", "run", file_path])
        if run_res.returncode not in (0, 1):
            print(f"\n❌ ERROR: 'mutmut run {file_path}' exited with unexpected status {run_res.returncode}")
            return run_res.returncode

    pr_survivors, legacy_survivors = _collect_survivor_info(targets)
    write_github_summary(pr_survivors, legacy_survivors, targets)

    if pr_survivors:
        print(f"\n❌ FAILED: {len(pr_survivors)} surviving mutant(s) found in modified lines!")
        return 1

    if legacy_survivors:
        print(f"\nℹ️ NOTE: {len(legacy_survivors)} pre-existing surviving mutant(s) in untouched lines were ignored.")

    print("\n🎉 All PR mutants killed successfully!")
    return 0


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/master"
    changed_lines = get_changed_lines_by_file(base)
    targets = filter_target_files(changed_lines)
    sys.exit(run_mutation_on_targets(targets))
