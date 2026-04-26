@echo off
for /f "delims=" %%i in ('git describe --tags --always --dirty') do set VERSION=%%i
for /f "delims=" %%i in ('git rev-parse --short HEAD') do set COMMIT=%%i
for /f "delims=" %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-ddTHH:mm:ssZ"') do set BUILD_DATE=%%i

set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0

go build -ldflags="-s -w -X 'main.Version=%VERSION%' -X 'main.Commit=%COMMIT%' -X 'main.BuildDate=%BUILD_DATE%'" -o cli-proxy-api.exe ./cmd/server/

echo Build complete: CLIProxyAPI.exe
