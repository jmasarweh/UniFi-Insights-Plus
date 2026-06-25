"""Tests for env-configurable connection-pool sizing helpers in db.py.

Covers env_int() and env_pool_bounds(): default fallback, parsing, invalid
input handling, minimum clamping, and min>max clamping.
"""

import db


def test_env_int_default(monkeypatch):
    monkeypatch.delenv('TEST_POOL_INT', raising=False)
    assert db.env_int('TEST_POOL_INT', 7) == 7


def test_env_int_parses_value(monkeypatch):
    monkeypatch.setenv('TEST_POOL_INT', '12')
    assert db.env_int('TEST_POOL_INT', 7) == 12


def test_env_int_blank_falls_back(monkeypatch):
    monkeypatch.setenv('TEST_POOL_INT', '   ')
    assert db.env_int('TEST_POOL_INT', 7) == 7


def test_env_int_invalid_falls_back(monkeypatch):
    monkeypatch.setenv('TEST_POOL_INT', 'not-a-number')
    assert db.env_int('TEST_POOL_INT', 7) == 7


def test_env_int_minimum_clamp(monkeypatch):
    monkeypatch.setenv('TEST_POOL_INT', '0')
    assert db.env_int('TEST_POOL_INT', 7, minimum=1) == 1


def test_pool_bounds_defaults(monkeypatch):
    monkeypatch.delenv('TEST_POOL_MIN', raising=False)
    monkeypatch.delenv('TEST_POOL_MAX', raising=False)
    assert db.env_pool_bounds('TEST_POOL_MIN', 'TEST_POOL_MAX', 2, 10) == (2, 10)


def test_pool_bounds_from_env(monkeypatch):
    monkeypatch.setenv('TEST_POOL_MIN', '4')
    monkeypatch.setenv('TEST_POOL_MAX', '15')
    assert db.env_pool_bounds('TEST_POOL_MIN', 'TEST_POOL_MAX', 2, 10) == (4, 15)


def test_pool_bounds_min_clamped_to_max(monkeypatch):
    monkeypatch.setenv('TEST_POOL_MIN', '20')
    monkeypatch.setenv('TEST_POOL_MAX', '10')
    assert db.env_pool_bounds('TEST_POOL_MIN', 'TEST_POOL_MAX', 2, 10) == (10, 10)


def test_pool_bounds_max_floor_of_one(monkeypatch):
    monkeypatch.setenv('TEST_POOL_MAX', '0')
    monkeypatch.delenv('TEST_POOL_MIN', raising=False)
    pool_min, pool_max = db.env_pool_bounds('TEST_POOL_MIN', 'TEST_POOL_MAX', 2, 10)
    assert pool_max == 1
    assert pool_min <= pool_max
