@echo off
setlocal
set TOOLS=%~dp0..\..\tools

echo == where a download would run on this machine ==
"%TOOLS%\dl.exe" tiers
echo.

echo == what is in the store, and whether anything is watching it ==
"%TOOLS%\jobd.exe" status
echo.

echo == how this install starts the supervisor ==
sc.exe qc OpenAbstractionsSupervisor >nul 2>&1
if errorlevel 1 goto :shortcut
echo   A per-user service. Windows starts it at every sign-in, in your own
echo   session and under your own account, and restarts it if it dies. This is
echo   what the "Everyone" install registered, once, with an administrator.
goto :done
:shortcut
echo   A shortcut in your Startup folder, run at your next sign-in. If the
echo   supervisor dies before then, nothing replaces it until you sign in
echo   again. This is what the "Just me" install can do without an
echo   administrator, and it is the whole difference between the two scopes.
:done

echo.
if /i "%~1"=="--no-pause" goto :eof
pause
