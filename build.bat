@echo off
rem File    : build.bat
rem Author  : Saksham Varshney
rem Roll No : 44300
rem Purpose : builds server.exe and client.exe (no libraries needed)
cd /d "%~dp0"

where g++ >nul 2>nul
if %errorlevel%==0 goto USE_GPP
where cl >nul 2>nul
if %errorlevel%==0 goto USE_CL

echo No C++ compiler found (g++ or cl).
echo Use the prebuilt server.exe and client.exe that are already in this folder.
pause
exit /b 1

:USE_GPP
echo Building with g++ ...
g++ -std=gnu++11 -O2 -Wall -static -static-libgcc -static-libstdc++ server.cpp -o server.exe -lws2_32
if errorlevel 1 goto FAIL
g++ -std=gnu++11 -O2 -Wall -static -static-libgcc -static-libstdc++ client.cpp -o client.exe -lws2_32
if errorlevel 1 goto FAIL
goto OK

:USE_CL
echo Building with Visual C++ ...
cl /nologo /EHsc /O2 server.cpp /Fe:server.exe
if errorlevel 1 goto FAIL
cl /nologo /EHsc /O2 client.cpp /Fe:client.exe
if errorlevel 1 goto FAIL
del /q server.obj client.obj >nul 2>nul
goto OK

:FAIL
echo.
echo BUILD FAILED - read the error message above.
pause
exit /b 1

:OK
echo.
echo Build finished: server.exe and client.exe are ready.
pause
exit /b 0