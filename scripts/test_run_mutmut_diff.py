# Copyright 2016-2026 the Advisor Backend team at Red Hat.
# This file is part of the Insights Advisor project.

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from run_mutmut_diff import (
    _get_git_diff_output,
    _extract_hunk_range,
    _parse_diff_lines,
    filter_target_files,
    parse_function_and_class_from_mutant_name,
    get_function_start_line,
    parse_mutant_relative_line,
    _collect_survivor_info,
    write_github_summary,
    run_mutation_on_targets,
)


class TestGitDiffSecurity:
    """Tests for Git diff input validation, error handling, and security."""

    def test_rejects_invalid_branch_names(self):
        with pytest.raises(ValueError, match="Invalid git base branch"):
            _get_git_diff_output("origin/master; rm -rf /")

        with pytest.raises(ValueError, match="Invalid git base branch"):
            _get_git_diff_output("master | cat")

    @patch("run_mutmut_diff.subprocess.run")
    def test_valid_branch_command_structure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="diff output")
        result = _get_git_diff_output("origin/main")
        assert result == "diff output"
        mock_run.assert_called_with(
            ["git", "diff", "-U0", "--diff-filter=d", "origin/main...HEAD", "--"],
            capture_output=True,
            text=True,
            check=False,
        )

    @patch("run_mutmut_diff.subprocess.run")
    def test_raises_runtime_error_when_git_fails(self, mock_run):
        mock_run.return_value = MagicMock(returncode=128, stderr="fatal: ambiguous argument")
        with pytest.raises(RuntimeError, match="Failed to compute git diff against 'origin/invalid'"):
            _get_git_diff_output("origin/invalid")


class TestDiffHunkParsing:
    """Tests for Git diff hunk parsing and line range extraction."""

    def test_extract_hunk_range_single_line_addition(self):
        line = "@@ -10 +25 @@ def sample():"
        hunk_range = _extract_hunk_range(line)
        assert hunk_range == range(25, 26)
        assert list(hunk_range) == [25]

    def test_extract_hunk_range_multi_line_addition(self):
        line = "@@ -10,3 +25,4 @@ def sample():"
        hunk_range = _extract_hunk_range(line)
        assert hunk_range == range(25, 29)
        assert list(hunk_range) == [25, 26, 27, 28]

    def test_extract_hunk_range_pure_deletion(self):
        line = "@@ -10,2 +25,0 @@"
        hunk_range = _extract_hunk_range(line)
        assert list(hunk_range) == []

    def test_extract_hunk_range_malformed_header(self):
        assert _extract_hunk_range("+++ b/service/service.py") is None
        assert _extract_hunk_range("not a hunk header") is None

    def test_parse_diff_lines_multiple_files(self):
        diff_text = """\
diff --git a/Pipfile b/Pipfile
--- a/Pipfile
+++ b/Pipfile
@@ -10 +10 @@
+mutmut = "*"
diff --git a/service/service.py b/service/service.py
--- a/service/service.py
+++ b/service/service.py
@@ -50,2 +50,3 @@
+def new_func():
    pass
    return True
@@ -100 +110,2 @@
+    x = 1
+    y = 2
diff --git a/docs/README.md b/docs/README.md
--- a/docs/README.md
+++ b/docs/README.md
@@ -1 +1 @@
+# Documentation
"""
        parsed = _parse_diff_lines(diff_text)
        assert "Pipfile" not in parsed
        assert "docs/README.md" not in parsed
        assert "service/service.py" in parsed
        assert parsed["service/service.py"] == {50, 51, 52, 110, 111}


class TestFilterTargetFiles:
    """Tests for target file exclusion rules."""

    def test_filter_target_files_business_logic_vs_ignored(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        service_file = tmp_path / "service" / "service.py"
        service_file.parent.mkdir(parents=True, exist_ok=True)
        service_file.write_text("def test(): pass")

        api_file = tmp_path / "api" / "advisor" / "api" / "filters.py"
        api_file.parent.mkdir(parents=True, exist_ok=True)
        api_file.write_text("def filter(): pass")

        changed_lines = {
            "service/service.py": {10, 11},
            "api/advisor/api/filters.py": {20},
            "api/advisor/api/migrations/0001_initial.py": {5},
            "service/tests/test_service.py": {15},
            "api/advisor/api/tests/test_views.py": {30},
            "api/advisor/api/admin.py": {8},
            "api/advisor/project_settings/settings.py": {40},
            "service/non_existent.py": {1},
        }

        targets = filter_target_files(changed_lines)
        assert "service/service.py" in targets
        assert "api/advisor/api/filters.py" in targets
        assert "api/advisor/api/migrations/0001_initial.py" not in targets
        assert "service/tests/test_service.py" not in targets
        assert "api/advisor/api/tests/test_views.py" not in targets
        assert "api/advisor/api/admin.py" not in targets
        assert "api/advisor/project_settings/settings.py" not in targets
        assert "service/non_existent.py" not in targets


class TestMutmutKeyAndLineResolution:
    """Tests for resolving Mutmut keys to AST start lines and file line numbers."""

    def test_parse_function_and_class_from_mutant_name(self):
        func, cls = parse_function_and_class_from_mutant_name(
            "api.advisor.api.filters.x_filter_by_staleness__mutmut_1"
        )
        assert func == "filter_by_staleness"
        assert cls is None

        func, cls = parse_function_and_class_from_mutant_name(
            "service.service.xǁEngineConsumerǁhandle_msg__mutmut_2"
        )
        assert func == "handle_msg"
        assert cls == "EngineConsumer"

    def test_get_function_start_line_top_level_and_methods(self, tmp_path):
        source = """\
import sys

def top_level_func(a, b):
    return a + b

class HelperClass:
    def method_one(self):
        return True

    async def async_method(self):
        return False
"""
        test_file = tmp_path / "sample.py"
        test_file.write_text(source)

        assert get_function_start_line(str(test_file), "top_level_func") == 3
        assert get_function_start_line(str(test_file), "method_one", "HelperClass") == 7
        assert get_function_start_line(str(test_file), "async_method", "HelperClass") == 10
        assert get_function_start_line(str(test_file), "unknown_func") == 1

    def test_parse_mutant_relative_line(self):
        diff_text = """\
--- service/service.py
+++ service/service.py
@@ -1,5 +1,5 @@
 def sample():
-    x = 1
+    x = 2
"""
        # Line 1 is "def sample():", Line 2 is the mutated "x = 1" line
        assert parse_mutant_relative_line(diff_text) == 2


class TestSurvivorPartitioning:
    """Tests for distinguishing PR survivors from legacy survivors."""

    @patch("run_mutmut_diff.get_diff_for_mutant")
    @patch("run_mutmut_diff.SourceFileMutationData")
    def test_collect_survivor_info_partitions_pr_and_legacy(
        self, mock_mutation_data_cls, mock_get_diff, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        sample_code = """\
def target_func():
    val = 10
    return val
"""
        service_dir = tmp_path / "service"
        service_dir.mkdir(parents=True, exist_ok=True)
        test_file = service_dir / "service.py"
        test_file.write_text(sample_code)

        mock_data = MagicMock()
        # Mutmut status codes: 0 = survived (tests passed with mutant), 1 = killed (tests failed)
        mock_data.exit_code_by_key = {
            "service.service.x_target_func__mutmut_1": 0,  # survived
            "service.service.x_target_func__mutmut_2": 0,  # survived
            "service.service.x_target_func__mutmut_3": 1,  # killed
        }
        mock_mutation_data_cls.return_value = mock_data

        diff_mutant_1 = """\
# service.service.x_target_func__mutmut_1: survived
--- service/service.py
+++ service/service.py
@@ -1,3 +1,3 @@
 def target_func():
-    val = 10
+    val = 11
"""
        diff_mutant_2 = """\
# service.service.x_target_func__mutmut_2: survived
--- service/service.py
+++ service/service.py
@@ -1,3 +1,3 @@
 def target_func():
     val = 10
-    return val
+    return None
"""
        def mock_diff_side_effect(mutant_id, path):
            if "mutmut_1" in mutant_id:
                return diff_mutant_1
            elif "mutmut_2" in mutant_id:
                return diff_mutant_2
            return ""

        mock_get_diff.side_effect = mock_diff_side_effect

        targets = {"service/service.py": {2}}

        pr_survivors, legacy_survivors = _collect_survivor_info(targets)

        assert len(pr_survivors) == 1
        assert pr_survivors[0]["name"] == "service.service.x_target_func__mutmut_1"
        assert pr_survivors[0]["line"] == 2

        assert len(legacy_survivors) == 1
        assert legacy_survivors[0]["name"] == "service.service.x_target_func__mutmut_2"
        assert legacy_survivors[0]["line"] == 3


class TestGitHubSummaryGeneration:
    """Tests for GITHUB_STEP_SUMMARY formatting."""

    def test_write_github_summary_only_when_pr_survivors_present(self, tmp_path, monkeypatch):
        summary_file = tmp_path / "step_summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

        pr_survivors = [
            {
                "name": "service.service.x_target_func__mutmut_1",
                "file": "service/service.py",
                "line": 52,
                "diff": "- return True\n+ return False",
            }
        ]
        legacy_survivors = [{"name": "legacy_mutant"}]
        targets = {"service/service.py": {52}}

        write_github_summary(pr_survivors, legacy_survivors, targets)
        assert summary_file.exists()
        content = summary_file.read_text()
        assert "Mutation Testing Alert (Action Required)" in content
        assert "service/service.py" in content
        assert "PR Surviving Mutants (New Code)" in content

        summary_file.unlink()
        write_github_summary([], legacy_survivors, targets)
        assert not summary_file.exists()


class TestMutmutExecution:
    """Tests for runner orchestration and exit codes."""

    @patch("run_mutmut_diff.run_mutmut")
    def test_run_mutation_on_targets_empty(self, mock_run):
        assert run_mutation_on_targets({}) == 0
        mock_run.assert_not_called()

    @patch("run_mutmut_diff._collect_survivor_info")
    @patch("run_mutmut_diff.write_github_summary")
    @patch("run_mutmut_diff.run_mutmut")
    def test_run_mutation_on_targets_pr_survivor_returns_1(
        self, mock_run, mock_summary, mock_collect
    ):
        mock_collect.return_value = ([{"name": "pr_mut"}], [])

        targets = {"service/service.py": {10}}
        exit_code = run_mutation_on_targets(targets)

        assert exit_code == 1
        mock_run.assert_called_once_with(["service/service.py"], max_children=None)
        mock_summary.assert_called_once()

    @patch("run_mutmut_diff._collect_survivor_info")
    @patch("run_mutmut_diff.write_github_summary")
    @patch("run_mutmut_diff.run_mutmut")
    def test_run_mutation_on_targets_clean_or_legacy_returns_0(
        self, mock_run, mock_summary, mock_collect
    ):
        mock_collect.return_value = ([], [{"name": "legacy_mut"}])

        targets = {"service/service.py": {10}}
        exit_code = run_mutation_on_targets(targets)

        assert exit_code == 0

    @patch("run_mutmut_diff.run_mutmut")
    def test_run_mutation_on_targets_fails_when_mutmut_errors(self, mock_run):
        mock_run.side_effect = SystemExit(2)
        targets = {"service/service.py": {10}}
        exit_code = run_mutation_on_targets(targets)
        assert exit_code == 2
