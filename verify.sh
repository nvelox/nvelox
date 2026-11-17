#!/bin/bash
# verification.sh

# Kill any existing instances
pkill -f "proxy-server"
pkill -f "mock_backend"

# Start Backends (mock servers)
go run tools/mock_backend/main.go > backend1.log 2>&1 &
PID1=$!

echo "Started backend on 8081"

# Start Proxy in debug mode
./nvelox -config nvelox.yaml > nvelox.log 2>&1 &
PROXY_PID=$!

echo "Started nvelox with PID $PROXY_PID"
sleep 2

# Send traffic to binding range
echo "Sending to 9000..."
# Keep connection open for 1s to allow async dial to finish
(echo "Request 1"; sleep 1) | nc 127.0.0.1 9000

sleep 1

# Check log
echo "--- Proxy Log ---"
cat nvelox.log
echo "-----------------"

echo "--- Backend 1 Log ---"
cat backend1.log
echo "---------------------"

# Cleanup
kill $PROXY_PID $PID1 $PID2

