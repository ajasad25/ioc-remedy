"""Subcommand discovery and argument wiring."""
import pytest

from ioc_remedy import cli


EXPECTED = {"scan", "scan-engine", "verify", "clean", "fix-gitignore",
            "restore", "remediate", "remediate-auto", "rollout"}


def test_every_command_module_is_discovered():
    names = {m.NAME for m in cli.discover()}
    assert EXPECTED <= names


def test_every_command_declares_help_and_a_docstring():
    for module in cli.discover():
        assert getattr(module, "HELP", ""), module.NAME
        assert (module.__doc__ or "").strip(), module.NAME


def test_parser_builds_for_every_command():
    parser = cli.build_parser(cli.discover())
    for name in sorted(EXPECTED):
        args = parser.parse_args([name] + _required_args(name))
        assert args.command == name


def _required_args(name):
    return ["--phase", "workflow"] if name == "rollout" else []


def test_common_flags_are_available_on_every_command():
    parser = cli.build_parser(cli.discover())
    args = parser.parse_args(["scan", "--workdir", "/tmp/x", "--account", "alice"])
    assert args.workdir == "/tmp/x"
    assert args.accounts == ["alice"]


def test_no_command_prints_help_and_returns_two(capsys):
    assert cli.main([]) == 2
    assert "usage:" in capsys.readouterr().out


def test_destructive_commands_default_to_dry_run():
    # The property that made these safe to iterate on during the incident.
    parser = cli.build_parser(cli.discover())
    for name, flag in (("clean", "execute"), ("fix-gitignore", "execute"),
                       ("restore", "execute"), ("remediate", "apply"),
                       ("remediate-auto", "apply")):
        args = parser.parse_args([name])
        assert getattr(args, flag) is False, name


def test_rollout_requires_an_explicit_phase():
    parser = cli.build_parser(cli.discover())
    with pytest.raises(SystemExit):
        parser.parse_args(["rollout"])
