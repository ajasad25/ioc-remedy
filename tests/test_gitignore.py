"""Detection and repair of the attacker's .gitignore tampering."""
from ioc_remedy import gitignore


def test_detects_marker():
    text = "node_modules\nconfig.bat\n"
    needed, marker, env = gitignore.inspect(text)
    assert needed and marker
    assert not env


def test_clean_gitignore_needs_no_repair():
    needed, marker, env = gitignore.inspect("node_modules\n.env\n")
    assert not needed
    assert not marker
    assert env


def test_repair_removes_marker_and_keeps_the_rest():
    repaired = gitignore.repair("node_modules\nconfig.bat\n.env\n")
    assert "config.bat" not in repaired
    assert "node_modules" in repaired
    assert ".env" in repaired


def test_repair_restores_env_rules_when_stripped():
    # The damaging half of the tampering: without these rules the next
    # `git add -A` stages a developer's environment file.
    repaired = gitignore.repair("node_modules\ndist\n")
    assert ".env" in repaired
    assert "!.env.example" in repaired


def test_repair_preserves_crlf_line_endings():
    repaired = gitignore.repair("node_modules\r\nconfig.bat\r\n.env\r\n")
    assert "\r\n" in repaired
    assert "\n\n" not in repaired.replace("\r\n", "\n\n").replace("\n\n", "\r\n")
    assert "config.bat" not in repaired


def test_repair_is_idempotent():
    once = gitignore.repair("node_modules\nconfig.bat\n")
    twice = gitignore.repair(once)
    assert once == twice


def test_env_variants_count_as_ignored():
    for pattern in (".env", ".env*", ".env.*", "*.env"):
        assert gitignore.ignores_env("node_modules\n{}\n".format(pattern)), pattern
