import pytest

from finguard.data.splits import SplitConfig, SplitError, assign_splits, assert_no_leakage, remove_near_duplicates
from finguard.data.label import fixture_targets
from _data_helpers import fixture_rows


@pytest.fixture(scope="module")
def cfg():
    return SplitConfig.load()


@pytest.fixture(scope="module")
def split_rows(cfg):
    return assign_splits(fixture_rows(3), cfg, allow_fixtures=True)


def test_fixture_rows_refused_without_flag(cfg):
    with pytest.raises(SplitError):
        assign_splits(fixture_rows(1), cfg, allow_fixtures=False)


def test_heldout_never_in_train_dev(split_rows, cfg):
    for r in split_rows:
        if r.split in ("train", "dev"):
            assert r.attack_family not in cfg.heldout_families
            assert r.workflow not in cfg.heldout_workflows
            assert r.policy_set not in cfg.heldout_policy_sets
    assert {r.split for r in split_rows if r.workflow == "payroll"} == {"test_heldout_workflow"}
    fams = {r.split for r in split_rows if r.attack_family in cfg.heldout_families}
    assert fams == {"test_heldout_family"}


def test_template_never_spans_splits(split_rows):
    seen = {}
    for r in split_rows:
        assert seen.setdefault(r.template_id, r.split) == r.split


def test_leak_check_catches_tampering(split_rows, cfg):
    bad = [r.model_copy(update={"split": "train"}) if r.workflow == "payroll" else r for r in split_rows]
    with pytest.raises(SplitError):
        assert_no_leakage(bad, cfg)
    one = next(r for r in split_rows if r.split == "test_iid")
    with pytest.raises(SplitError):
        assert_no_leakage(split_rows + [one.model_copy(update={"split": "train", "example_id": "dup"})], cfg)


@pytest.mark.parametrize("method", ["exact", "minhash_lsh"])
def test_near_dup_removal(split_rows, cfg, method):
    train = next(r for r in split_rows if r.split == "train")
    clone = train.model_copy(update={"example_id": "clone", "split": "test_iid", "template_id": "other.tmpl"})
    rows, rep = remove_near_duplicates(split_rows + [clone], cfg, method=method)
    assert "clone" in rep.dropped_ids and all(r.example_id != "clone" for r in rows)
    assert rep.max_jaccard_kept <= cfg.near_dup.jaccard_max
    assert sum(r.split == "train" for r in rows) == sum(r.split == "train" for r in split_rows)


def test_every_category_in_train(split_rows):
    cats = {r.gold_category for r in split_rows}
    assert cats == {r.gold_category for r in split_rows if r.split == "train"}
