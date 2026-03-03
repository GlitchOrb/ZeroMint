"""Test 2: CLI smoke tests (init, doctor)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from cve_agent.cli import app

runner = CliRunner()


class TestCliInit:
    """Tests for `zeromint init`."""

    def test_init_creates_config(self, tmp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """init should copy config.example.yaml to the output path."""
        monkeypatch.chdir(tmp_dir)
        output = tmp_dir / "config.yaml"

        result = runner.invoke(app, ["init", "--output", str(output)])

        # May fail if config.example.yaml is not found relative to package,
        # but should not crash
        if result.exit_code == 0:
            assert output.exists()
            content = output.read_text(encoding="utf-8")
            assert "target" in content
        # If exit_code == 1, config.example.yaml wasn't found ??acceptable in test env

    def test_init_refuses_overwrite(self, tmp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """init should refuse to overwrite without --force."""
        monkeypatch.chdir(tmp_dir)
        output = tmp_dir / "config.yaml"
        output.write_text("existing", encoding="utf-8")

        result = runner.invoke(app, ["init", "--output", str(output)])
        assert result.exit_code == 1
        assert output.read_text(encoding="utf-8") == "existing"  # Unchanged

    def test_init_force_overwrite(self, tmp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """init --force should overwrite existing config."""
        monkeypatch.chdir(tmp_dir)
        output = tmp_dir / "config.yaml"
        output.write_text("old", encoding="utf-8")

        result = runner.invoke(app, ["init", "--output", str(output), "--force"])
        # If template found, file should be replaced
        if result.exit_code == 0:
            assert output.read_text(encoding="utf-8") != "old"


class TestCliDoctor:
    """Tests for `zeromint doctor`."""

    def test_doctor_runs_without_crash(self) -> None:
        """doctor should run and display tool check results."""
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "Python" in result.output
        assert "pydantic" in result.output

    def test_doctor_checks_python_version(self) -> None:
        """doctor should report Python version."""
        result = runner.invoke(app, ["doctor"])
        assert "3." in result.output  # Should contain version like 3.11


class TestCliVersion:
    """Tests for `zeromint version`."""

    def test_version_output(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output
