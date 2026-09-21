@echo off
rem Starts the Engramic Baseline app without leaving a console window open.
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0Start-CEAuditGui.ps1"
