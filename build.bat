@echo off
setlocal
echo [*] Building phantom-ssh for Windows (amd64)...
set CGO_ENABLED=0
go build -ldflags="-s -w" -trimpath -o phantom-ssh.exe main.go

echo [*] Cross-compiling phantom-ssh for Linux (amd64)...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -trimpath -o phantom-ssh main.go

echo [+] Build completed successfully.
dir phantom-ssh*
