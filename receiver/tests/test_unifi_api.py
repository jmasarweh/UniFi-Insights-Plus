"""Tests for unifi_api.py — bulk patch retry, concurrency, verification."""

import threading
import time
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import requests

from unifi_api import UniFiAPI


def _make_http_error(status_code, body='error'):
    """Build a real requests.HTTPError with a mocked response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = body
    err = requests.HTTPError(response=resp)
    return err


@pytest.fixture
def api():
    """Create a UniFiAPI with a mocked DB (skips _resolve_config)."""
    mock_db = MagicMock()
    mock_db.get_config = MagicMock(return_value=None)
    mock_db.set_config = MagicMock()
    with patch.object(UniFiAPI, '_resolve_config'):
        uapi = UniFiAPI(mock_db)
    uapi.host = 'https://fake-controller'
    uapi.api_key = 'test-key'
    uapi.enabled = True
    uapi._site_uuid = 'fake-site-uuid'
    # Pre-init session so _get_session() doesn't try real HTTP
    uapi._session = MagicMock()
    return uapi


# ── _patch_one_policy ────────────────────────────────────────────────────────


class TestPatchOnePolicy:
    def test_success(self, api):
        api.patch_firewall_policy = MagicMock(return_value={'id': 'p1'})
        result = api._patch_one_policy('p1', True)
        assert result['status'] == 'success'
        assert result['retried'] == 0
        api.patch_firewall_policy.assert_called_once_with('p1', True)

    @patch('unifi_api.time.sleep')
    def test_retry_on_429(self, mock_sleep, api):
        """429 on first attempt should retry, succeed on second."""
        api.patch_firewall_policy = MagicMock(
            side_effect=[_make_http_error(429), {'id': 'p1'}]
        )
        result = api._patch_one_policy('p1', True)
        assert result['status'] == 'success'
        assert result['retried'] == 1
        assert api.patch_firewall_policy.call_count == 2
        mock_sleep.assert_called_once_with(0.5)

    @patch('unifi_api.time.sleep')
    def test_retry_on_502(self, mock_sleep, api):
        """502 on first two attempts, succeed on third."""
        api.patch_firewall_policy = MagicMock(
            side_effect=[_make_http_error(502), _make_http_error(502), {'id': 'p1'}]
        )
        result = api._patch_one_policy('p1', False)
        assert result['status'] == 'success'
        assert result['retried'] == 2
        assert api.patch_firewall_policy.call_count == 3
        # Backoff: 0.5s, 1.0s
        assert mock_sleep.call_count == 2

    @patch('unifi_api.time.sleep')
    def test_exhausted_retries_on_429(self, mock_sleep, api):
        """Three 429s in a row should exhaust retries and fail."""
        api.patch_firewall_policy = MagicMock(
            side_effect=[_make_http_error(429), _make_http_error(429), _make_http_error(429)]
        )
        result = api._patch_one_policy('p1', True)
        assert result['status'] == 'failed'
        assert result['id'] == 'p1'
        assert 'HTTP 429' in result['error']
        # Only 2 retries (first attempt is not a retry)
        assert result['retried'] == 2

    def test_non_retryable_http_error(self, api):
        """A 400 should fail immediately without retry."""
        api.patch_firewall_policy = MagicMock(
            side_effect=_make_http_error(400, 'bad request')
        )
        result = api._patch_one_policy('p1', True)
        assert result['status'] == 'failed'
        assert 'HTTP 400' in result['error']
        assert result['retried'] == 0
        api.patch_firewall_policy.assert_called_once()

    def test_non_http_exception(self, api):
        """Connection errors and other exceptions should fail immediately."""
        api.patch_firewall_policy = MagicMock(
            side_effect=ConnectionError('refused')
        )
        result = api._patch_one_policy('p1', True)
        assert result['status'] == 'failed'
        assert 'refused' in result['error']
        assert result['retried'] == 0


# ── bulk_patch_logging ───────────────────────────────────────────────────────


class TestBulkPatchLogging:
    def test_all_succeed(self, api):
        """All policies patch successfully → success count matches."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
            {'id': 'p3', 'loggingEnabled': True},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
            {'id': 'p3', 'loggingEnabled': True},
        ]
        result = api.bulk_patch_logging(updates)

        assert result['total'] == 3
        assert result['success'] == 3
        assert result['failed'] == 0
        assert result['skipped'] == 0
        assert result['errors'] == []

    def test_skips_none_logging(self, api):
        """Items with loggingEnabled=None should be skipped, not patched."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2'},  # no loggingEnabled key
            {'id': 'p3', 'loggingEnabled': None},
        ]
        result = api.bulk_patch_logging(updates)

        assert result['total'] == 3
        assert result['success'] == 1
        assert result['skipped'] == 2
        # Only p1 should have been patched
        api.patch_firewall_policy.assert_called_once()

    def test_mixed_success_and_failure(self, api):
        """Some patches fail, others succeed — counts are correct."""
        call_count = 0
        def mock_patch(pid, val):
            nonlocal call_count
            call_count += 1
            if pid == 'p2':
                raise _make_http_error(400, 'invalid')
            return {}

        api.patch_firewall_policy = mock_patch
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p3', 'loggingEnabled': True},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
            {'id': 'p3', 'loggingEnabled': True},
        ]
        result = api.bulk_patch_logging(updates)

        assert result['success'] == 2
        assert result['failed'] == 1
        assert len(result['errors']) == 1
        assert result['errors'][0]['id'] == 'p2'

    def test_verification_detects_mismatch(self, api):
        """Verification catches policies that report success but didn't actually apply."""
        api.patch_firewall_policy = MagicMock(return_value={})
        # Controller returns loggingEnabled=False for p2 even though patch "succeeded"
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': False},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ]
        result = api.bulk_patch_logging(updates)

        # p2 patched "successfully" but verification caught the mismatch
        assert result['success'] == 1
        assert result['failed'] == 1
        assert any('verification' in e for e in result['errors'])

    def test_verification_does_not_double_count_patch_failures(self, api):
        """A policy that failed during patching should NOT be re-counted as a verification failure."""
        def mock_patch(pid, val):
            if pid == 'p2':
                raise _make_http_error(500, 'server error')
            return {}

        api.patch_firewall_policy = mock_patch
        # p2 still shows old state (loggingEnabled=False) since patch failed
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': False},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ]
        result = api.bulk_patch_logging(updates)

        # p2 should only be counted once as a patch failure, not double-counted
        assert result['failed'] == 1
        assert result['success'] == 1

    def test_verification_failure_is_graceful(self, api):
        """If get_firewall_policies raises during verification, it's logged but doesn't crash."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(side_effect=ConnectionError('timeout'))

        updates = [{'id': 'p1', 'loggingEnabled': True}]
        result = api.bulk_patch_logging(updates)

        # Patch itself succeeded
        assert result['success'] == 1
        # Verification error is appended but doesn't change success count
        assert any('verification' in e for e in result['errors'])
        assert 'timeout' in result['errors'][0]['verification']

    def test_progress_callback_called(self, api):
        """progress_callback receives incremental updates during patching."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ])

        progress_events = []
        def on_progress(completed, total, success, failed, phase='patching'):
            progress_events.append({
                'completed': completed, 'total': total,
                'success': success, 'failed': failed, 'phase': phase,
            })

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ]
        api.bulk_patch_logging(updates, progress_callback=on_progress)

        # At least 2 patching events + 1 verifying event
        patching_events = [e for e in progress_events if e['phase'] == 'patching']
        verifying_events = [e for e in progress_events if e['phase'] == 'verifying']
        assert len(patching_events) == 2
        assert len(verifying_events) == 1
        # Final patching event should show completed == total
        assert patching_events[-1]['completed'] == 2
        assert patching_events[-1]['total'] == 2

    def test_progress_callback_exception_does_not_crash(self, api):
        """A broken progress_callback should not prevent bulk_patch from completing."""
        api.patch_firewall_policy = MagicMock(return_value={})
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
        ])

        def bad_callback(*args, **kwargs):
            raise RuntimeError('callback crashed')

        updates = [{'id': 'p1', 'loggingEnabled': True}]
        result = api.bulk_patch_logging(updates, progress_callback=bad_callback)

        # Should still complete successfully despite callback explosions
        assert result['success'] == 1
        assert result['failed'] == 0

    def test_concurrency_actually_parallel(self, api):
        """Verify that 4 workers actually run concurrently, not sequentially."""
        # Track concurrent execution with threading primitives
        max_concurrent = 0
        current_concurrent = 0
        lock = threading.Lock()

        def slow_patch(pid, val):
            nonlocal max_concurrent, current_concurrent
            with lock:
                current_concurrent += 1
                max_concurrent = max(max_concurrent, current_concurrent)
            time.sleep(0.05)  # simulate controller latency
            with lock:
                current_concurrent -= 1
            return {}

        api.patch_firewall_policy = slow_patch
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': f'p{i}', 'loggingEnabled': True} for i in range(8)
        ])

        updates = [{'id': f'p{i}', 'loggingEnabled': True} for i in range(8)]
        result = api.bulk_patch_logging(updates)

        assert result['success'] == 8
        # With 4 workers and 8 items, we should see >1 concurrent execution
        assert max_concurrent > 1, f"Expected parallel execution but max_concurrent={max_concurrent}"

    def test_empty_updates(self, api):
        """Empty update list should return immediately with zero counts."""
        api.get_firewall_policies = MagicMock()
        result = api.bulk_patch_logging([])

        assert result['total'] == 0
        assert result['success'] == 0
        assert result['failed'] == 0
        assert result['skipped'] == 0
        # Should NOT call get_firewall_policies (no verification needed)
        api.get_firewall_policies.assert_not_called()

    @patch('unifi_api.time.sleep')
    def test_retried_count_aggregated(self, mock_sleep, api):
        """The retried counter in the result should sum retries across all policies."""
        call_counts = {}
        def mock_patch(pid, val):
            call_counts[pid] = call_counts.get(pid, 0) + 1
            if call_counts[pid] == 1:
                raise _make_http_error(429)
            return {}

        api.patch_firewall_policy = mock_patch
        api.get_firewall_policies = MagicMock(return_value=[
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ])

        updates = [
            {'id': 'p1', 'loggingEnabled': True},
            {'id': 'p2', 'loggingEnabled': True},
        ]
        result = api.bulk_patch_logging(updates)

        assert result['success'] == 2
        assert result['retried'] == 2  # each policy retried once
