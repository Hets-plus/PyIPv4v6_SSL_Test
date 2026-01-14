@echo off
setlocal
set PYTHON27=python
if "%~1"=="" (
  %PYTHON27% "%~dp0\main.py"
  goto :eof
)
%PYTHON27% "%~dp0\main.py" %*