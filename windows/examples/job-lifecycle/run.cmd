@echo off
setlocal
set TOOLS=%~dp0..\..\tools
set STORE=%TEMP%\openabstractions-example-store
set ABSTRACTION_STORE=%STORE%
set JOB_STORE=%STORE%
set CTL="%TOOLS%\jobctl.exe"

echo A throwaway store, so this touches nothing you rely on:
echo   %STORE%
echo.

echo == submit ==  an application says what it wants done
%CTL% submit --kind download --spec "{\"url\":\"https://example.com/big.iso\"}" --total 1000 > "%STORE%.id"
set ID=
set /p ID=<"%STORE%.id"
del "%STORE%.id"
if not defined ID goto :failed
echo   job %ID%
%CTL% list
echo.

echo == claim ==  one worker takes it, for 60 seconds, and gets an epoch
%CTL% claim --owner example --ttl 60 %ID%
echo.
echo   The epoch is the point. A second worker that claims this job gets epoch
echo   2, and every write the first one still tries is refused. That is how one
echo   job survives two programs without a lock.
echo.

echo == progress ==  reported against the epoch you hold
%CTL% progress --epoch 1 --done 400 %ID%
%CTL% progress --epoch 1 --done 1000 %ID%
echo.

echo == a stale epoch is refused ==
%CTL% progress --epoch 0 --done 7 %ID%
echo   ^(that failure is the example working^)
echo.

echo == finish ==
%CTL% finish --epoch 1 --state complete %ID%
%CTL% show %ID%
echo.

echo Delete %STORE% when you are done with it.
echo.
if /i "%~1"=="--no-pause" goto :eof
pause
goto :eof

:failed
echo   jobctl submit produced no job id. Nothing else here can run.
exit /b 1
