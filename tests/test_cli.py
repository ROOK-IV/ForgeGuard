import json
import sys

from forgeguard.cli import main


def test_main_renders_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "forgeguard.cli.inspect_running_containers",
        lambda: [],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["forgeguard", "--format", "json"],
    )

    exit_code = main()
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 0
    assert report["summary"]["warned"] == 1
    assert report["findings"][0]["check_id"] == "docker.running-containers"


def test_main_uses_text_format_by_default(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "forgeguard.cli.inspect_running_containers",
        lambda: [],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["forgeguard"],
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "FORGEGUARD AUDIT" in captured.out
    assert "Running containers" in captured.out
    assert "Result: 0 passed, 1 warned, 0 failed" in captured.out