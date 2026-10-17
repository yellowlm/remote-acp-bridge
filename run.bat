@echo off
rem Background control for a locally running remote-acp-server (see devrun.py):
rem   run.bat start --config ..\Dev\run\local.toml
rem   run.bat status --config ..\Dev\run\local.toml
rem   run.bat logs
rem   run.bat stop
setlocal
cd /d "%~dp0"
set "PY=%PYTHON%"
if "%PY%"=="" set "PY=python"
"%PY%" devrun.py %*
set "RC=%ERRORLEVEL%"
endlocal
exit /b %RC%
