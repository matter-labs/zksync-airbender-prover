#!/usr/bin/env python3
"""Minimal fake prover API for SNARK prover Docker repros.

It implements only:
  POST /prover-jobs/v1/SNARK/pick?id=...
  POST /prover-jobs/v1/SNARK/submit?id=...
"""

import argparse
import json
import pathlib
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class FakeSnarkHandler(BaseHTTPRequestHandler):
    job_bytes = b""
    max_picks = 0
    picks_served = 0
    submissions_seen = 0
    submit_dir = pathlib.Path(".")

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)
        prover_id = query.get("id", [""])[0]

        if path == "/prover-jobs/v1/SNARK/pick":
            self._handle_snark_pick(prover_id)
            return

        if path == "/prover-jobs/v1/SNARK/submit":
            self._handle_snark_submit(prover_id)
            return

        if path == "/prover-jobs/v1/FRI/pick":
            self._send_no_content()
            return

        self.send_error(404, f"unsupported endpoint: {path}")

    def _handle_snark_pick(self, prover_id):
        unlimited = self.max_picks == 0
        if unlimited or self.picks_served < self.max_picks:
            type(self).picks_served += 1
            limit = "unlimited" if unlimited else str(self.max_picks)
            print(
                f"SNARK pick from prover={prover_id!r}: serving job "
                f"{self.picks_served}/{limit}",
                flush=True,
            )
            self._send_json_bytes(self.job_bytes)
        else:
            print(
                f"SNARK pick from prover={prover_id!r}: no content",
                flush=True,
            )
            self._send_no_content()

    def _handle_snark_submit(self, prover_id):
        content_length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(content_length)

        type(self).submissions_seen += 1
        path = self.submit_dir / (
            f"snark_submit_{int(time.time())}_{self.submissions_seen}.json"
        )
        path.write_bytes(body)

        try:
            payload = json.loads(body)
            proof_len = len(payload.get("proof", ""))
            summary = (
                f"from={payload.get('from_batch_number')} "
                f"to={payload.get('to_batch_number')} "
                f"vk_hash={payload.get('vk_hash')} "
                f"proof_base64_bytes={proof_len}"
            )
        except Exception as exc:
            summary = f"invalid JSON submit body: {exc}"

        print(
            f"SNARK submit from prover={prover_id!r}: saved {path} ({summary})",
            flush=True,
        )
        self._send_json_bytes(b'{"status":"ok"}')

    def _send_json_bytes(self, body):
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_no_content(self):
        self.send_response(204)
        self.send_header("content-length", "0")
        self.end_headers()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--job-file",
        default="crates/zksync_os_snark_prover/src/bin/batch_204254.json",
        help="GetSnarkProofPayload JSON to return from SNARK/pick",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=33124)
    parser.add_argument(
        "--max-picks",
        type=int,
        default=0,
        help="number of times to serve the job; 0 means unlimited",
    )
    parser.add_argument(
        "--submit-dir",
        default="outputs/fake-snark-submissions",
        help="directory where SNARK/submit request bodies are saved",
    )
    args = parser.parse_args()

    job_path = pathlib.Path(args.job_file)
    job_bytes = job_path.read_bytes()
    job = json.loads(job_bytes)

    required = {"from_batch_number", "to_batch_number", "vk_hash", "fri_proofs"}
    missing = sorted(required - set(job))
    if missing:
        raise SystemExit(f"{job_path} is missing required keys: {missing}")

    submit_dir = pathlib.Path(args.submit_dir)
    submit_dir.mkdir(parents=True, exist_ok=True)

    FakeSnarkHandler.job_bytes = job_bytes
    FakeSnarkHandler.max_picks = args.max_picks
    FakeSnarkHandler.submit_dir = submit_dir

    server = ThreadingHTTPServer((args.host, args.port), FakeSnarkHandler)
    print(
        f"Serving SNARK job {job_path} on http://{args.host}:{args.port} "
        f"(max_picks={args.max_picks}, submit_dir={submit_dir})",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
