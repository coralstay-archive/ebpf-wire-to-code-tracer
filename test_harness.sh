#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "================================================================================"
echo "[1/7] Building Stripped Shared Library: libcrypto_mock.cpp -> libcrypto_mock.so"
echo "================================================================================"
clang++ -std=c++17 -g -O0 -fno-inline -fno-omit-frame-pointer -fPIC -shared \
    libcrypto_mock.cpp -o libcrypto_mock.so
strip -x libcrypto_mock.so

echo "================================================================================"
echo "[2/7] Building Multi-Threaded Target Server: mock_server.cpp -> mock_server"
echo "================================================================================"
clang++ -std=c++17 -g -O0 -fno-inline -fno-omit-frame-pointer -pthread \
    mock_server.cpp -ldl -o mock_server

echo "================================================================================"
echo "[3/7] Starting mock_server in background & verifying live TCP HTTP response"
echo "================================================================================"
./mock_server --port 18080 --once &
SERVER_PID=$!
python3 -c '
import socket, time
for attempt in range(30):
    try:
        with socket.create_connection(("127.0.0.1", 18080), timeout=1.0) as s:
            s.sendall(b"GET /api/v1/query HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer tok_123\r\n\r\n")
            resp = s.recv(1024).decode("utf-8", errors="replace")
            if "200 OK" in resp:
                print("Live TCP HTTP check passed:", resp.splitlines()[0])
                break
    except OSError:
        time.sleep(0.1)
else:
    raise RuntimeError("Failed to connect to mock_server on port 18080")
'
wait "$SERVER_PID" || true

echo "================================================================================"
echo "[4/7] Running Step 1: Baseline Full 7-Layer Trace (--net-layer all)"
echo "================================================================================"
python3 tracer_agent.py \
    --mode simulate \
    --binary ./mock_server \
    --lib ./libcrypto_mock.so \
    --port 8080 \
    --net-layer all \
    --out trace_baseline \
    --ai-report ai_diagnosis_baseline.json \
    --html-out trace_dashboard.html

echo "================================================================================"
echo "[5/7] Running Step 2: Ring Buffer Overflow Alert Graph (--simulate-drops 128)"
echo "================================================================================"
python3 tracer_agent.py \
    --mode simulate \
    --binary ./mock_server \
    --lib ./libcrypto_mock.so \
    --port 8080 \
    --simulate-drops 128 \
    --out trace_overflow \
    --ai-report ai_diagnosis_overflow.json

echo "================================================================================"
echo "[6/7] Running Step 3 & 4: Zoom-In Probe, --fast-mode Patch & --compare Report"
echo "================================================================================"
python3 tracer_agent.py \
    --mode simulate \
    --binary ./mock_server \
    --lib ./libcrypto_mock.so \
    --port 8080 \
    --focus-symbol "execute_storage_query" \
    --out trace_zoom \
    --ai-report ai_diagnosis_zoom.json

python3 tracer_agent.py \
    --mode simulate \
    --binary ./mock_server \
    --lib ./libcrypto_mock.so \
    --port 8080 \
    --fast-mode \
    --out trace_patched \
    --ai-report ai_diagnosis_patched.json \
    --compare ai_diagnosis_baseline.json ai_diagnosis_patched.json

echo "================================================================================"
echo "[7/7] Running Full 24-Suite Verification (TEST-01..12 + ADV-TEST-01..12)"
echo "================================================================================"
if python3 -c "import pytest" >/dev/null 2>&1; then
    python3 -m pytest test_verification_suite.py -v
elif [ -x "/opt/homebrew/anaconda3/bin/pytest" ]; then
    /opt/homebrew/anaconda3/bin/pytest test_verification_suite.py -v
else
    python3 test_verification_suite.py -v
fi
