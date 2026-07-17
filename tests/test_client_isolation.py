"""Parallel upload client isolation and aggregate limiter sharing."""

from __future__ import annotations

from types import SimpleNamespace

from megabasterd_cli.core.api import MegaAPIClient
from megabasterd_cli.core.client import MegaClient, MegaSession
from megabasterd_cli.core.downloader import MegaDownloader
from megabasterd_cli.core.uploader import MegaUploader
from megabasterd_cli.utils.speed import TokenBucket


def test_worker_api_clients_have_isolated_sessions_and_sequences():
    a = MegaAPIClient()
    b = MegaAPIClient()
    assert a._session is not b._session, "requests.Session must not be shared"
    a_seq, b_seq = a._seq, b._seq
    a._build_url()
    assert a._seq == a_seq + 1
    assert b._seq == b_seq, "sequence counters must not be shared across clients"


def test_client_close_does_not_invalidate_shared_server_session():
    requests_sent: list = []

    class _RecordingAPI(MegaAPIClient):
        def request(self, commands, extra_params=None):
            requests_sent.append(commands)
            return {}

    base = MegaClient(api=_RecordingAPI())
    session = MegaSession(sid="sid", master_key=b"\x00" * 16, email="a@x")
    base.session = session

    worker_api = _RecordingAPI()
    worker = MegaClient(api=worker_api)
    worker.session = session
    worker_api.set_session(session.sid)

    worker.close()
    assert requests_sent == [], "close() must not send a logout (sml) request"
    assert worker.session is None
    assert base.session is session, "the base client keeps the session material"


def test_one_worker_failure_does_not_corrupt_another_clients_state():
    api1, api2 = MegaAPIClient(), MegaAPIClient()
    c1, c2 = MegaClient(api=api1), MegaClient(api=api2)
    session = MegaSession(sid="sid", master_key=b"\x01" * 16)
    c1.session = session
    c2.session = session
    c1._node_cache = [SimpleNamespace(handle="x")]
    c2.invalidate_cache()
    assert c1._node_cache is not None, "node caches are per client"
    c1.close()
    assert c2.session is session


def test_downloader_and_uploader_share_a_supplied_limiter():
    shared = TokenBucket(rate=1024)
    d1 = MegaDownloader(api=None, speed_limit_kbps=999, limiter=shared)
    d2 = MegaDownloader(api=None, speed_limit_kbps=999, limiter=shared)
    assert d1.limiter is shared and d2.limiter is shared

    client = SimpleNamespace(
        session=SimpleNamespace(master_key=b"\x00" * 16),
        api=None,
        find_root=lambda: "root",
        invalidate_cache=lambda: None,
    )
    u1 = MegaUploader(client=client, speed_limit_kbps=999, limiter=shared)
    u2 = MegaUploader(client=client, speed_limit_kbps=999, limiter=shared)
    assert u1.limiter is shared and u2.limiter is shared


def test_folder_parallel_workers_share_the_parent_limiter():
    """The per-worker downloaders in folder mode adopt the parent's limiter."""
    import inspect

    from megabasterd_cli.core import folder_downloader as fd

    # The parallel branch constructs a fresh MegaDownloader per worker and
    # must rebind it to the parent's limiter (aggregate cap), never build a
    # second one from the configured rate.
    src = inspect.getsource(fd.MegaFolderDownloader._download_file_jobs)
    assert "worker_dl.limiter = self.downloader.limiter" in src
