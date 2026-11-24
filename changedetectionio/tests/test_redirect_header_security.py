"""Application-level regression probe for cross-origin redirect header forwarding.

This test uses only loopback HTTP servers and synthetic credentials. It creates a
watch through the public API, lets the real scheduler/worker run it, and records
what the redirect destination receives.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from changedetectionio.tests.util import wait_for_all_checks


def _serve(server):
    Thread(target=server.serve_forever, daemon=True).start()


def test_api_created_watch_forwards_sensitive_headers_to_cross_origin_redirect(
    client, live_server, measure_memory_usage
):
    received = []

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/collect")
            self.end_headers()

        def log_message(self, *_args):
            pass

    class SinkHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append({key.lower(): value for key, value in self.headers.items()})
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

        assert received, "The redirect sink was never reached by the application worker"
        leaked = received[-1]
        assert leaked.get("authorization") == synthetic_headers["Authorization"]
        assert leaked.get("x-api-key") == synthetic_headers["X-API-Key"]
        assert leaked.get("cookie") == synthetic_headers["Cookie"]
    finally:
        source.shutdown()
        sink.shutdown()
        source.server_close()
        sink.server_close()
