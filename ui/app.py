
from pathlib import Path
import json
import os
import subprocess
import sys
import threading

from flask import Flask, jsonify, render_template

ROOT = Path(__file__).resolve().parent.parent
REPORT_FILE = ROOT / "reports" / "report.json"
CONFIG_FILE = ROOT / "domains.yml"
CHECKER_FILE = ROOT / "cert_checker.py"

app = Flask(__name__)
check_lock = threading.Lock()


def read_report():
    if not REPORT_FILE.exists():
        return {
            "overall": "unknown",
            "counts": {
                "failed": 0,
                "critical": 0,
                "warning": 0,
                "ok": 0,
            },
            "thresholds": {
                "warn_days": 30,
                "critical_days": 7,
            },
            "results": [],
            "generated_at": None,
            "message": "No report found. Run a certificate check first.",
        }

    with REPORT_FILE.open(encoding="utf-8") as file:
        return json.load(file)


@app.get("/")
def dashboard():
    return render_template("index.html")


@app.get("/api/report")
def report():
    try:
        return jsonify(read_report())
    except (OSError, json.JSONDecodeError) as exc:
        return jsonify({"error": f"Unable to read report: {exc}"}), 500


@app.post("/api/check")
def run_check():
    if not check_lock.acquire(blocking=False):
        return jsonify({"error": "A certificate check is already running."}), 409

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(CHECKER_FILE),
                "--config",
                str(CONFIG_FILE),
                "--out",
                str(REPORT_FILE.parent),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

        try:
            data = read_report()
        except (OSError, json.JSONDecodeError):
            data = {"results": [], "counts": {}, "overall": "unknown"}

        data["check_exit_code"] = result.returncode
        data["check_output"] = result.stdout[-12000:]
        data["check_errors"] = result.stderr[-4000:]

        return jsonify(data), 200 if result.returncode == 0 else 422

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Certificate check timed out after 180 seconds."}), 504
    except OSError as exc:
        return jsonify({"error": f"Could not start certificate checker: {exc}"}), 500
    finally:
        check_lock.release()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
