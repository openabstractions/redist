@echo off
setlocal
set OA="%~dp0..\..\tools\openabstractions.exe"
set KEY=example-lifecycle-%RANDOM%%RANDOM%
set URL=http://127.0.0.1:9/never

echo A job from submitted to ended, one command per step, through the runtime
echo this install runs. The source is a port on this machine that nothing
echo answers, so the work stays unfinished until it is cancelled. Nothing is
echo downloaded and no internet is needed.
echo.

echo == submit ==  the request identity %KEY% is chosen before anything is sent
%OA% download %URL% --key %KEY% --no-wait
if errorlevel 1 goto :failed
echo.

echo == observe ==  pending or running: the runtime keeps trying the port
%OA% jobs show --key %KEY%
echo.

echo == cancel ==  records the intent to cancel, which is not proof it stopped
%OA% jobs cancel --key %KEY%
echo.

echo == wait ==  follows the job until it ends
%OA% jobs wait --key %KEY% --timeout 60s
echo   ^(exit 5, cancelled: that is the example working^)
echo.

echo == cancel again ==  nothing is left to cancel, and no work is created
%OA% jobs cancel --key %KEY%
echo.

echo == submit the same request again ==  the same job comes back
%OA% download %URL% --key %KEY% --no-wait
echo.

echo == retry ==  a new attempt is accepted only after the last one failed
%OA% download %URL% --key %KEY% --no-wait --retry
echo   ^(exit 3, invalid: a cancelled job is not retried^)
echo.

echo == a request the runtime cannot perform ==  refused before anything is sent
%OA% download ftp://127.0.0.1/never
echo   ^(exit 2^)
echo.

echo The job stays in this program's list: openabstractions jobs list
echo.
if /i "%~1"=="--no-pause" goto :eof
pause
goto :eof

:failed
echo   The runtime did not accept the job. openabstractions status says whether
echo   it is running.
exit /b 1
