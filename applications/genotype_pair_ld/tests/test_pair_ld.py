from __future__ import annotations

import importlib.util
import math
import pathlib
import sys

import pytest

BUNDLE_ROOT = pathlib.Path(__file__).resolve().parent.parent / "signed"


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


local_data_owner = _load("genotype_pair_ld_local_data_owner", BUNDLE_ROOT / "local_data_owner.py")
local_project_owner = _load(
    "genotype_pair_ld_local_project_owner", BUNDLE_ROOT / "local_project_owner.py"
)
server = _load("genotype_pair_ld_server", BUNDLE_ROOT / "server.py")


class PlaintextEvaluator:
    def add(self, a, b):
        return [left + right for left, right in zip(a, b)]

    def mul(self, a, b):
        return [left * right for left, right in zip(a, b)]


def _plain_aggregate(raw_records: list, pair_count: int) -> dict:
    encoded = [local_data_owner.encode(raw, pair_count) for raw in raw_records]
    pairs = [
        (
            local_data_owner.append_sentinel(record["a"]),
            local_data_owner.append_sentinel(record["b"]),
        )
        for record in encoded
    ]
    return server.aggregate(pairs, PlaintextEvaluator())


def _oracle(raw_records: list, pair_count: int) -> dict:
    encoded = [local_data_owner.encode(raw, pair_count) for raw in raw_records]
    n = len(encoded)
    sums = {
        "sum_g_a": [0] * pair_count,
        "sum_g_b": [0] * pair_count,
        "sum_g_a2": [0] * pair_count,
        "sum_g_b2": [0] * pair_count,
        "sum_g_a_g_b": [0] * pair_count,
    }
    for record in encoded:
        for index, (a, b) in enumerate(zip(record["a"], record["b"])):
            sums["sum_g_a"][index] += a
            sums["sum_g_b"][index] += b
            sums["sum_g_a2"][index] += a * a
            sums["sum_g_b2"][index] += b * b
            sums["sum_g_a_g_b"][index] += a * b

    mean_a = [value / n for value in sums["sum_g_a"]]
    mean_b = [value / n for value in sums["sum_g_b"]]
    variance_a = [
        sums["sum_g_a2"][index] / n - mean_a[index] ** 2
        for index in range(pair_count)
    ]
    variance_b = [
        sums["sum_g_b2"][index] / n - mean_b[index] ** 2
        for index in range(pair_count)
    ]
    covariance = [
        sums["sum_g_a_g_b"][index] / n - mean_a[index] * mean_b[index]
        for index in range(pair_count)
    ]
    r2 = []
    for index in range(pair_count):
        denom = variance_a[index] * variance_b[index]
        r2.append(None if denom <= 0 else (covariance[index] ** 2) / denom)

    return {
        **sums,
        "n_contributors": n,
        "mean_g_a": mean_a,
        "mean_g_b": mean_b,
        "variance_g_a": variance_a,
        "variance_g_b": variance_b,
        "covariance": covariance,
        "r2": r2,
    }


def _assert_decoded_matches_oracle(decoded: dict, expected: dict) -> None:
    for key in ["sum_g_a", "sum_g_b", "sum_g_a2", "sum_g_b2", "sum_g_a_g_b"]:
        assert decoded[key] == expected[key]
    assert decoded["n_contributors"] == expected["n_contributors"]
    for key in ["mean_g_a", "mean_g_b", "variance_g_a", "variance_g_b", "covariance"]:
        assert decoded[key] == pytest.approx(expected[key], abs=0.0, rel=0.0)
    for got, want in zip(decoded["r2"], expected["r2"]):
        if want is None:
            assert got is None
        else:
            assert got == pytest.approx(want, abs=1e-12, rel=0.0)


def test_cleartext_aggregate_matches_adjacent_pair_oracle():
    raw_records = [
        [0, 1, 2, 0],
        [1, 1, 0, 2],
        [2, 0, 1, 1],
        [0, 2, 2, 2],
    ]
    pair_count = 3

    plain = _plain_aggregate(raw_records, pair_count)
    decoded = local_project_owner.decode(plain, pair_count)

    assert decoded["pair_count"] == pair_count
    _assert_decoded_matches_oracle(decoded, _oracle(raw_records, pair_count))


def test_cleartext_aggregate_matches_bounded_pair_list_oracle():
    pairs = [[0, 2], [1, 4], [3, 4]]
    raw_records = [
        {"genotype": [0, 1, 2, 0, 2], "pairs": pairs},
        {"genotype": [1, 1, 0, 2, 1], "pairs": pairs},
        {"genotype": [2, 0, 1, 1, 0], "pairs": pairs},
        {"genotype": [0, 2, 2, 2, 2], "pairs": pairs},
    ]
    pair_count = len(pairs)

    plain = _plain_aggregate(raw_records, pair_count)
    decoded = local_project_owner.decode(plain, pair_count)

    _assert_decoded_matches_oracle(decoded, _oracle(raw_records, pair_count))


def test_zero_variance_pair_reports_null_r2():
    raw_records = [
        [1, 0, 2],
        [1, 1, 1],
        [1, 2, 0],
    ]
    pair_count = 2

    decoded = local_project_owner.decode(_plain_aggregate(raw_records, pair_count), pair_count)

    assert decoded["variance_g_a"][0] == 0
    assert decoded["r"][0] is None
    assert decoded["r2"][0] is None
    assert math.isfinite(decoded["r2"][1])


def test_rejects_malformed_pair_list():
    with pytest.raises(ValueError, match="does not match"):
        local_data_owner.encode({"genotype": [0, 1, 2], "pairs": [[0, 1]]}, 2)


def test_local_loop_he_matches_cleartext_oracle():
    pytest.importorskip("tenseal", reason="TenSEAL not installed")
    raw_records = [
        [0, 1, 2],
        [1, 1, 0],
        [2, 0, 1],
    ]
    pair_count = 2

    secret_context, public_context = local_project_owner.keygen(security=256)
    ciphertexts = [
        local_data_owner.encrypt(public_context, local_data_owner.encode(raw, pair_count))
        for raw in raw_records
    ]
    result_bytes = server.compute(ciphertexts, public_context)
    plain = local_project_owner.decrypt(secret_context, result_bytes)
    decoded = local_project_owner.decode(plain, pair_count)

    _assert_decoded_matches_oracle(decoded, _oracle(raw_records, pair_count))
