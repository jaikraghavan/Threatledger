from __future__ import annotations

import pytest

from threatledger.coverage.engine import (
    Coverage,
    TechniqueCoverage,
    coverage_from_statuses,
    summarise,
    technique_coverage,
)


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], Coverage.GAP),
        (["not_implemented"], Coverage.GAP),
        (["planned"], Coverage.GAP),
        (["partial"], Coverage.PARTIAL),
        (["planned", "partial"], Coverage.PARTIAL),
        (["partial", "implemented"], Coverage.COVERED),
        (["bogus"], Coverage.GAP),
    ],
)
def test_coverage_from_best_control(statuses, expected):
    assert coverage_from_statuses(statuses) is expected


def test_subtechnique_inherits_parent_when_better():
    # 1 = parent (implemented control), 2 = sub-technique (no own control), 3 = sub with partial
    result = technique_coverage(
        [1, 2, 3],
        controls_by_technique={1: {10}, 3: {11}},
        control_status={10: "implemented", 11: "partial"},
        parent_of={2: 1, 3: 1},
    )
    assert result[1].status is Coverage.COVERED and not result[1].inherited
    assert result[2].status is Coverage.COVERED and result[2].inherited
    assert result[2].own_status is Coverage.GAP
    assert result[3].status is Coverage.COVERED and result[3].own_status is Coverage.PARTIAL


def test_parent_does_not_roll_up_from_children():
    result = technique_coverage(
        [1], controls_by_technique={2: {10}}, control_status={10: "implemented"}, parent_of={}
    )
    assert result[1].status is Coverage.GAP


def test_unknown_controls_are_ignored():
    result = technique_coverage([1], {1: {99}}, {}, {})
    assert result[1].status is Coverage.GAP
    assert result[1].control_ids == frozenset({99})


def test_summary_percent_weights_partial_half():
    cov = [
        TechniqueCoverage(1, Coverage.COVERED, Coverage.COVERED, False, frozenset()),
        TechniqueCoverage(2, Coverage.PARTIAL, Coverage.PARTIAL, False, frozenset()),
        TechniqueCoverage(3, Coverage.GAP, Coverage.GAP, False, frozenset()),
        TechniqueCoverage(4, Coverage.GAP, Coverage.GAP, False, frozenset()),
    ]
    s = summarise(cov)
    assert (s.covered, s.partial, s.gap, s.total) == (1, 1, 2, 4)
    assert s.percent == 38  # (1 + 0.5) / 4
    assert summarise([]).percent == 0


def test_coverage_labels():
    assert Coverage.PARTIAL.label == "Partial"
    assert Coverage.COVERED.css == "covered"
