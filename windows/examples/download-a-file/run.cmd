@echo off
setlocal
set OA=%~dp0..\..\tools\openabstractions.exe
set OUT=%TEMP%\openabstractions-example-download
set URL=https://www.rfc-editor.org/rfc/rfc9110.txt
set SHA256=21c1cdce6ab0e5509b04d84a28000836c7a087cf786efe6f04877ebfff47232a

echo This one needs the internet. The runtime fetches 491 KiB, and this
echo command copies the result into
echo   %OUT%
echo.

if not exist "%OUT%" mkdir "%OUT%"
"%OA%" download %URL% --sha256 %SHA256% --out "%OUT%"
set CODE=%ERRORLEVEL%
if not "%CODE%"=="0" goto :failed

echo.
echo == what this program has asked the runtime for ==
"%OA%" jobs list
echo.
echo The runtime checked the digest before the result existed; this command
echo only copied the result out. Run this twice: the second run names the same
echo job and copies the same result, because the request identity is derived
echo from the request itself.
echo.
echo Close this window half way and run it again: the download did not stop,
echo because it belongs to the runtime and not to this window.
echo.
if /i "%~1"=="--no-pause" goto :eof
pause
goto :eof

:failed
echo.
if "%CODE%"=="1" echo   No runtime answered. "%OA%" status says whether it is running.
if "%CODE%"=="4" echo   The runtime could not decide right now. Run this again later.
if "%CODE%"=="5" echo   The download ended. If the failure says digest_mismatch, this file
if "%CODE%"=="5" echo   changed at the source: RFC 9110 is published immutable, so that would
if "%CODE%"=="5" echo   be news. After any other failure, add --retry to the download line.
exit /b %CODE%
