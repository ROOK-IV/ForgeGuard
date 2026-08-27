import json
import sys

from forgeguard.cli import main
from types import SimpleNamespace


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


def test_main_can_fail_on_warning(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "forgeguard.cli.inspect_running_containers",
        lambda: [],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["forgeguard", "--fail-on", "warn"],
    )

    exit_code = main()
    capsys.readouterr()

    assert exit_code == 1


def test_main_reports_missing_container_filter(
    monkeypatch,
    capsys,
) -> None:
    running_containers = [
        SimpleNamespace(name="example-web"),
    ]

    monkeypatch.setattr(
        "forgeguard.cli.inspect_running_containers",
        lambda: running_containers,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["forgeguard", "--container", "missing-api"],
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Container filter" in captured.out
    assert 'No running container named "missing-api" was found.' in captured.out


def test_main_audits_only_selected_container(
    monkeypatch,
    capsys,
) -> None:
    running_containers = [
        SimpleNamespace(name="example-web"),
        SimpleNamespace(name="example-db"),
    ]
    audited_containers = []

    def fake_audit(containers) -> list:
        audited_containers.extend(containers)
        return []

    monkeypatch.setattr(
        "forgeguard.cli.inspect_running_containers",
        lambda: running_containers,
    )
    monkeypatch.setattr(
        "forgeguard.cli.audit_containers",
        fake_audit,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["forgeguard", "--container", "example-db"],
    )

    exit_code = main()
    capsys.readouterr()

    assert exit_code == 0
    assert len(audited_containers) == 1
    assert audited_containers[0].name == "example-db"