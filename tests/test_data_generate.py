import pytest

from finguard.data.generate import RetrieverPool, generate_examples, GenerationError
from finguard.data.templates import WORKFLOWS, Template
from finguard.schema import STOP_VERDICTS, evidence_is_grounded
from _data_helpers import fixture_rows, fixture_templates


def test_fixture_coverage():
    ts = fixture_templates()
    assert all(t.author == "claude-fixture" for t in ts)
    for wf in WORKFLOWS:
        w = [t for t in ts if t.workflow == wf]
        assert len({t.attack_family for t in w if t.is_attack}) >= 2, wf
        benign = [t for t in w if t.gold_verdict.value == "allow"]
        assert len(benign) >= 2 and any(t.benign_kind == "lookalike" for t in benign), wf
    assert any(t.gold_verdict.value == "escalate" and t.gold_category.value == "policy_violation" for t in ts)


def test_fixture_entities_are_fake():
    text = "\n".join(r.request.model_dump_json() for r in fixture_rows(3))
    import re
    for dom in re.findall(r"@([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)", text):
        assert dom.endswith(".example"), dom
    assert re.findall(r"ACCT-\d{4}-\d{4}", text)


def test_determinism_same_seed_same_rows():
    a = [r.model_dump_json() for r in fixture_rows(3, seed=11)]
    b = [r.model_dump_json() for r in fixture_rows(3, seed=11)]
    c = [r.model_dump_json() for r in fixture_rows(3, seed=12)]
    assert a == b and a != c


def test_trigger_span_grounded_and_policies_filled():
    for r in fixture_rows(3):
        assert r.request.policy_clauses, r.example_id
        if r.gold_verdict in STOP_VERDICTS:
            assert r.gold_trigger_span and evidence_is_grounded(r.gold_trigger_span, r.request)
        assert r.provenance.fixture_only and r.provenance.source == "synthetic_v1"


def test_ungrounded_trigger_raises():
    t = fixture_templates()[0].model_copy(update={"trigger_span": "text that is not in the row at all"})
    with pytest.raises(GenerationError):
        generate_examples(t, 1, 0, RetrieverPool())


def test_human_author_not_fixture_only():
    t = fixture_templates()[0].model_copy(update={"author": "human:jdoe"})
    (row,) = generate_examples(t, 1, 0, RetrieverPool())
    assert row.provenance.fixture_only is False and row.provenance.template_author == "human:jdoe"


def test_template_validation():
    base = fixture_templates()[0].model_dump()
    with pytest.raises(ValueError):
        Template.model_validate({**base, "trigger_span": None})
    with pytest.raises(ValueError):
        Template.model_validate({**base, "attack_family": None})
