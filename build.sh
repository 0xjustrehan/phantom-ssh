#!/usr/bin/env bash
set -e

echo "[*] Building phantom-ssh for Linux (amd64)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o phantom-ssh main.go

echo "[*] Cross-compiling phantom-ssh for Windows (amd64)..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o phantom-ssh.exe main.go

echo "[+] Build completed successfully."
ls -lh phantom-ssh*
