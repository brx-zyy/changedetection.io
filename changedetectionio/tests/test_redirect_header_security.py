"""Application-level regression probe for cross-origin redirect header forwarding.

This test uses only loopback HTTP servers and synthetic credentials. It creates a
watch through the public API, lets the real scheduler/worker run it, and records
what the redirect destination receives.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from changedetectionio.tests.util import wait_for_all_checks

from changedetectionio.content_fetchers.requests import _headers_for_redirect


def test_redirect_headers_preserved_for_same_origin():
    headers = {"Authorization": "Bearer synthetic-secret"}
    assert _headers_for_redirect(headers, "https://example.com/start", "https://example.com:443/next") is headers


def test_redirect_headers_dropped_for_different_port():
    headers = {"Authorization": "Bearer synthetic-secret"}
    assert _headers_for_redirect(headers, "http://example.com:8080/start", "http://example.com:8081/next") == {}


def test_redirect_headers_dropped_for_different_scheme():
    headers = {"Authorization": "Bearer synthetic-secret"}
    assert _headers_for_redirect(headers, "http://example.com/start", "https://example.com/next") == {}


def test_redirect_headers_dropped_when_origin_cannot_be_parsed():
    headers = {"Authorization": "Bearer synthetic-secret"}
    assert _headers_for_redirect(headers, "not a valid URL", "also invalid") == {}


def _serve(server):
    Thread(target=server.serve_forever, daemon=True).start()


def test_api_created_watch_does_not_forward_sensitive_headers_to_cross_origin_redirect(
    client, live_server, measure_memory_usage
):
    source_received = []
    sink_received = []

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            source_received.append({key.lower(): value for key, value in self.headers.items()})
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/collect")
            self.end_headers()

        def log_message(self, *_args):
            pass

    class SinkHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            sink_received.append({key.lower(): value for key, value in self.headers.items()})
            body = b"redirect sink reached"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    source = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
    _serve(source)
    _serve(sink)

    try:
        datastore = client.application.config["DATASTORE"]
        api_key = datastore.data["settings"]["application"]["api_access_token"]
        synthetic_headers = {
            "Authorization": "Bearer integration-test-secret",
            "X-API-Key": "integration-test-api-key",
            "Cookie": "session=integration-test-cookie",
        }

        response = client.post(
            "/api/v1/watch",
            headers={"x-api-key": api_key},
            json={
                "url": f"http://127.0.0.1:{source.server_port}/start",
                "fetch_backend": "html_requests",
                "headers": synthetic_headers,
                "paused": False,
            },
        )
        assert response.status_code == 201, response.get_data(as_text=True)
        watch_uuid = response.get_json()["uuid"]

        # Explicitly queue the newly created watch through the public API.
        queued = client.get(
            "/api/v1/watch?recheck_all=1",
            headers={"x-api-key": api_key},
        )
        assert queued.status_code in (200, 202), queued.get_data(as_text=True)
        wait_for_all_checks(client)
        watch = datastore.data["watching"][watch_uuid]
        assert not watch.get("last_error"), watch.get("last_error")

        assert source_received, "The source endpoint was never reached"
        assert sink_received, "The redirect sink was never reached by the application worker"

        # Prove the watch sent the configured credentials to the intended origin.
        initial_headers = source_received[0]
        assert initial_headers.get("authorization") == synthetic_headers["Authorization"]
        assert initial_headers.get("x-api-key") == synthetic_headers["X-API-Key"]
        assert initial_headers.get("cookie") == synthetic_headers["Cookie"]

        # Every request received by the redirected origin must be credential-free.
        for redirected_headers in sink_received:
            assert "authorization" not in redirected_headers
            assert "x-api-key" not in redirected_headers
            assert "cookie" not in redirected_headers
    finally:
        source.shutdown()
        sink.shutdown()
        source.server_close()
        sink.server_close()
