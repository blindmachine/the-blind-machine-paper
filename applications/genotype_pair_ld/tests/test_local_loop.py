from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1] / "signed"


def load(name: str):
    path = ROOT / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def expected(vectors):
    pair_count = len(vectors[0]) - 1
    out = {name: [0] * pair_count for name in ("sum_g_a", "sum_g_b", "sum_g_a2", "sum_g_b2", "sum_g_a_g_b")}
    for vector in vectors:
        for index in range(pair_count):
            a = vector[index]
            b = vector[index + 1]
            out["sum_g_a"][index] += a
            out["sum_g_b"][index] += b
            out["sum_g_a2"][index] += a * a
            out["sum_g_b2"][index] += b * b
            out["sum_g_a_g_b"][index] += a * b
    return out


def test_encode_adjacent_pairs():
    data_owner = load("local_data_owner")
    assert data_owner.encode([0, 1, 2, 1], 3) == {"a": [0, 1, 2], "b": [1, 2, 1]}


def test_local_encrypted_loop_matches_cleartext():
    pytest.importorskip("tenseal")
    data_owner = load("local_data_owner")
    project_owner = load("local_project_owner")
    server = load("server")

    vectors = [
        [0, 1, 2, 1, 0],
        [1, 1, 1, 2, 0],
        [2, 1, 0, 1, 1],
        [0, 0, 1, 1, 2],
    ]
    pair_count = len(vectors[0]) - 1
    secret, public = project_owner.keygen(security=256)
    encoded = [data_owner.encode(vector, pair_count) for vector in vectors]
    ciphertexts = [data_owner.encrypt(public, item) for item in encoded]
    result = server.compute(ciphertexts, public)
    plain = project_owner.decrypt(secret, result)
    decoded = project_owner.decode(plain, pair_count)
    exp = expected(vectors)
    for key, value in exp.items():
        assert decoded[key] == value
    assert decoded["n_contributors"] == len(vectors)
    assert decoded["pair_count"] == pair_count
