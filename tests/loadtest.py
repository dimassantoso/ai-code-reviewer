#!/usr/bin/env python3
"""Scalability probe: blast signed webhooks at a real server with a stub hermes.

    python3 tests/loadtest.py --requests 200 --concurrency 32 --workers 4

Reports throughput, latency percentiles, and the peak number of concurrent
reviews, which must never exceed MAX_WORKERS.
"""
import argparse
import hashlib
import hmac
import json
import os
import queue
import statistics
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server  # noqa: E402

SECRET = "loadsecret"
peak = 0
inflight = 0
peak_lock = threading.Lock()


class Api(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = json.dumps({"changes": [{"new_path": "a.py", "diff": "+x"}], "overflow": False}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        body = b'{"id":1}'
        self.send_response(201)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    global peak, inflight
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=200)
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--review-ms", type=int, default=50, help="stub review duration")
    ap.add_argument("--queue", type=int, default=100, help="pending-job queue size")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp()
    stub = os.path.join(tmp, "hermes")
    with open(stub, "w") as fh:
        fh.write("#!/bin/sh\ncat >/dev/null\nsleep %s\nprintf 'LGTM\\n'\n" % (args.review_ms / 1000))
    os.chmod(stub, 0o755)
    os.environ.update(HERMES_BIN=stub, GITLAB_TOKEN="t", GITLAB_WEBHOOK_SECRET=SECRET)

    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()

    server.MAX_WORKERS = args.workers
    server._jobs = queue.Queue(maxsize=args.queue)
    server._workers_started = False
    real_process = server.process

    def counted(*a, **k):
        global peak, inflight
        with peak_lock:
            inflight += 1
            peak = max(peak, inflight)
        try:
            return real_process(*a, **k)
        finally:
            with peak_lock:
                inflight -= 1

    server.process = counted
    config = {"gitlab": {"token": "t", "secret": SECRET,
                         "url": f"http://127.0.0.1:{api.server_address[1]}"}}
    httpd = server.Server(("127.0.0.1", 0), server.Handler)
    httpd.config = config
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    statuses, latencies, errors = [], [], []
    lock = threading.Lock()
    next_id = iter(range(1, args.requests + 1))

    def worker():
        while True:
            with lock:
                n = next(next_id, None)
            if n is None:
                return
            raw = json.dumps({"object_kind": "merge_request", "project": {"id": n},
                              "object_attributes": {"iid": n, "action": "open"}}).encode()
            req = Request(base + "/gl-review", data=raw, method="POST",
                          headers={"X-Gitlab-Token": SECRET, "X-Gitlab-Event": "Merge Request Hook"})
            started = time.perf_counter()
            try:
                with urlopen(req, timeout=30) as resp:
                    code = resp.status
            except HTTPError as error:
                code = error.code
            except Exception as error:  # connection reset etc.
                code = type(error).__name__
            elapsed = time.perf_counter() - started
            with lock:
                statuses.append(code)
                if isinstance(code, int):
                    latencies.append(elapsed)
                else:
                    errors.append(code)

    start = time.perf_counter()
    pool = [threading.Thread(target=worker) for _ in range(min(args.concurrency, args.requests))]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    wall = time.perf_counter() - start

    deadline = time.time() + 60
    while time.time() < deadline and inflight:
        time.sleep(0.05)
    time.sleep(0.2)

    counts = {}
    for s in statuses:
        counts[s] = counts.get(s, 0) + 1
    lat = sorted(latencies) or [0]

    def pct(p):
        return lat[min(len(lat) - 1, int(len(lat) * p))] * 1000

    print(f"requests={args.requests} concurrency={args.concurrency} workers={args.workers}")
    print(f"wall={wall:.2f}s  throughput={args.requests / wall:.0f} req/s")
    print("statuses=" + json.dumps({str(k): v for k, v in sorted(counts.items(), key=lambda kv: str(kv[0]))}))
    print(f"latency ms  p50={pct(0.5):.1f}  p95={pct(0.95):.1f}  max={lat[-1] * 1000:.1f}")
    print(f"peak concurrent reviews={peak} (limit {args.workers})  queue={args.queue}")
    if errors:
        print("transport errors:", errors[:5])

    httpd.shutdown()
    api.shutdown()
    ok = peak <= args.workers and not errors
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
