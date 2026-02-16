"""Tests for CLI."""

import json
import tempfile
import os
from src.cli import analyze_permissions, main


def test_analyze_permissions_basic():
    permissions = [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"]}
    ]
    result = analyze_permissions(permissions)
    assert result["risk_score"] == 0


def test_analyze_permissions_with_risks():
    permissions = [{"Effect": "Allow", "Action": ["s3:*"], "Resource": ["*"]}]
    result = analyze_permissions(permissions)
    assert result["risk_score"] == 65
    assert len(result["findings"]) > 0


def test_analyze_permissions_deny_ignored():
    permissions = [{"Effect": "Deny", "Action": ["s3:*"], "Resource": ["*"]}]
    result = analyze_permissions(permissions)
    assert result["risk_score"] == 0


def test_cli_with_temp_file(monkeypatch):
    permissions = [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"]}
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(permissions, f)
        temp_path = f.name

    try:
        monkeypatch.setattr("sys.argv", ["cli", temp_path])
        exit_code = main()
        assert exit_code == 0
    finally:
        os.unlink(temp_path)


def test_cli_no_args(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["cli"])
    exit_code = main()
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Usage" in captured.out


def test_cli_invalid_json(monkeypatch, capsys):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("{invalid json}")
        temp_path = f.name

    try:
        monkeypatch.setattr("sys.argv", ["cli", temp_path])
        exit_code = main()
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out
    finally:
        os.unlink(temp_path)


def test_cli_file_not_found(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["cli", "/nonexistent/file.json"])
    exit_code = main()
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "not found" in captured.out
