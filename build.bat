@echo off
rem Build the Remote ACP Bridge: syntax check, unit tests, dist + zip into ..\Dev\build
setlocal
cd /d "%~dp0"
set "PY=%PYTHON%"
if "%PY%"=="" set "PY=python"
"%PY%" build.py %*
set "RC=%ERRORLEVEL%"
endlocal
exit /b %RC%
