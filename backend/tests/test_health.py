import threading

from app.config.settings import load_settings
from app.workers import worker
from app.workers.heartbeat import HEARTBEAT_KEY, beat
from tests.conftest import TEST_ENV, FakeRedis


def test_liveness(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok" and body["service"] == "TrustChain-X" and body["version"]


def test_readiness_is_degraded_without_a_worker(client):
    response = client.get("/api/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["mongodb"]["ok"] is True
    assert body["checks"]["redis"]["ok"] is True
    assert body["checks"]["worker"] == {"ok": False, "last_heartbeat": None}


def test_readiness_is_ok_when_worker_has_reported(client, fake_redis):
    stamp = beat(fake_redis, 10)
    body = client.get("/api/health/ready").json()
    assert body["status"] == "ok"
    assert body["checks"]["worker"] == {"ok": True, "last_heartbeat": stamp}


def test_readiness_is_degraded_when_redis_is_down(client, fake_redis):
    fake_redis.available = False
    response = client.get("/api/health/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
    assert response.json()["checks"]["redis"]["ok"] is False


def test_readiness_is_503_when_mongodb_is_down(client, app, monkeypatch):
    def fail(*_args, **_kwargs):
        raise ConnectionError("mongo down")

    monkeypatch.setattr(app.state.db, "command", fail)
    response = client.get("/api/health/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "unavailable"
    assert response.json()["checks"]["mongodb"]["ok"] is False


def test_health_endpoints_do_not_require_authentication(client):
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/health/ready").status_code == 200


def test_worker_heartbeat_loop_publishes_until_stopped():
    settings = load_settings({**TEST_ENV, "WORKER_HEARTBEAT_SECONDS": "1"})
    redis_client = FakeRedis()
    stop = threading.Event()
    original_set = redis_client.set

    def set_then_stop(*args, **kwargs):
        result = original_set(*args, **kwargs)
        stop.set()
        return result

    redis_client.set = set_then_stop
    assert worker.heartbeat_loop(settings, redis_client, stop) == 1
    assert redis_client.get(HEARTBEAT_KEY) is not None


def test_worker_heartbeat_survives_redis_outage():
    settings = load_settings({**TEST_ENV, "WORKER_HEARTBEAT_SECONDS": "1"})
    stop = threading.Event()

    class Broken:
        def set(self, *_a, **_k):
            stop.set()
            raise ConnectionError("down")

    assert worker.heartbeat_loop(settings, Broken(), stop) == 0
