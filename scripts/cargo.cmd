@echo off
setlocal
cd /d "%~dp0.."
cargo.exe %*
exit /b %errorlevel%
