@echo off
REM ====================================================================
REM StegoCrypt Desktop Application Launcher (Windows)
REM ====================================================================
TITLE Image Encryption & Steganography Engine

echo [*] Starting Image Encryption & Steganography Desktop Application...

IF EXIST "venv\Scripts\activate.bat" (
    echo [*] Activating Python virtual environment...
    call venv\Scripts\activate.bat
) ELSE IF EXIST ".venv\Scripts\activate.bat" (
    echo [*] Activating Python virtual environment (.venv)...
    call .venv\Scripts\activate.bat
)

python gui.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Application exited with an error code: %ERRORLEVEL%
    pause
)
