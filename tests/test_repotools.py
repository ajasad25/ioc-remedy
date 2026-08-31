"""Working-tree helpers used by both remediation commands."""
from ioc_remedy import repotools


def test_parse_findings_reads_engine_output():
    output = ("src/a.js:1: [ioc:wallet] something\n"
              "noise line\n"
              "tailwind.config.js:12: [heuristic:long-line] something\n")
    assert repotools.parse_findings(output) == [
        ("src/a.js", "ioc:wallet"),
        ("tailwind.config.js", "heuristic:long-line"),
    ]


def test_strip_payload_cuts_the_padded_tail(tmp_path):
    original = "module.exports = {};"
    target = tmp_path / "tailwind.config.js"
    target.write_text(original + " " * 507 + "X" * 1500 + "\n")

    cuts = repotools.strip_payload(str(target))

    assert cuts, "expected the padded tail to be cut"
    assert target.read_text() == original + "\n"


def test_strip_payload_leaves_a_clean_file_alone(tmp_path):
    target = tmp_path / "vite.config.js"
    target.write_text("export default {\n  plugins: [],\n}\n")
    before = target.read_text()

    assert repotools.strip_payload(str(target)) == []
    assert target.read_text() == before


def test_strip_payload_ignores_a_short_trailing_run(tmp_path):
    # A 300-space run with a short tail is formatting, not a payload.
    target = tmp_path / "x.js"
    body = "const a = 1;" + " " * 320 + "// note\n"
    target.write_text(body)

    assert repotools.strip_payload(str(target)) == []
    assert target.read_text() == body


def test_strip_payload_missing_file_is_not_an_error(tmp_path):
    assert repotools.strip_payload(str(tmp_path / "nope.js")) == []
