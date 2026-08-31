"""The marker registry and the classification helpers built on it."""
from ioc_remedy import iocs


def test_markers_are_lowercase_and_unique():
    # Bodies are lowercased before comparison, so an uppercase marker could
    # never match. This is the invariant that made the five copied lists safe
    # to merge.
    assert iocs.MARKERS == [m.lower() for m in iocs.MARKERS]
    assert len(iocs.MARKERS) == len(set(iocs.MARKERS))


def test_union_is_at_least_as_wide_as_any_original_list():
    # The pre-refactor scripts carried 15, 15, 10, 11 and 11 markers.
    assert len(iocs.MARKERS) >= 15


def test_find_markers_is_case_insensitive():
    marker = iocs.MARKERS[0]
    assert iocs.find_markers(marker.upper()) == [marker]


def test_find_markers_returns_empty_for_ordinary_source():
    body = "export default {\n  plugins: [],\n}\n"
    assert iocs.find_markers(body) == []


def test_longest_line():
    assert iocs.longest_line("ab\nabcd\na") == 4
    assert iocs.longest_line("") == 0


def test_looks_infected_flags_a_long_line_with_no_marker():
    suspicious, reasons = iocs.looks_infected("x" * (iocs.LONG_LINE_THRESHOLD + 1))
    assert suspicious
    assert any("long line" in r for r in reasons)


def test_looks_infected_ignores_ordinary_config():
    suspicious, reasons = iocs.looks_infected("module.exports = { theme: {} }\n")
    assert not suspicious
    assert reasons == []


def test_is_scannable_skips_vendored_and_small_files():
    big = iocs.MIN_PAYLOAD_SIZE + 1
    assert iocs.is_scannable("src/app.js", big)
    assert not iocs.is_scannable("node_modules/x/index.js", big)
    assert not iocs.is_scannable("src/app.js", iocs.MIN_PAYLOAD_SIZE - 1)
    assert not iocs.is_scannable("README.md", big)


def test_is_scannable_skips_security_tooling_that_legitimately_holds_markers():
    big = iocs.MIN_PAYLOAD_SIZE + 1
    assert not iocs.is_scannable("tools/iocs.txt", big)
