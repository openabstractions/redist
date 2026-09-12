@echo off
setlocal
set TOOLS=%~dp0..\..\tools
set OUT=%TEMP%\openabstractions-example-download
set URL=https://www.rfc-editor.org/rfc/rfc9110.txt
set DIGEST=sha256:21c1cdce6ab0e5509b04d84a28000836c7a087cf786efe6f04877ebfff47232a

echo This one needs the internet. It fetches 491 KiB into
echo   %OUT%
echo and uses your real store, so the job it creates shows up in dl list.
echo.

if not exist "%OUT%" mkdir "%OUT%"
"%TOOLS%\dl.exe" %URL% -o "%OUT%" --digest %DIGEST%
if errorlevel 1 goto :failed

echo.
echo == what the store says about it now ==
"%TOOLS%\dl.exe" list
echo.
echo The digest is an identity, not a checksum: given one, dl looks for those
echo exact bytes in the content-addressed stores already on this machine before
echo it fetches anything. Run this twice and watch the second run.
echo.
echo Interrupt it half way and run it again: it resumes from what it proved,
echo which is the thing curl -C - cannot promise.
echo.
if /i "%~1"=="--no-pause" goto :eof
pause
goto :eof

:failed
echo.
echo   dl failed. If the digest is what it refused, this file changed at the
echo   source: RFC 9110 is published immutable, so that would be news.
exit /b 1
