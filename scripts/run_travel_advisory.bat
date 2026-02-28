@echo off
REM Travel Advisory Report Generator - Scheduled Task
REM Runs every Friday to generate an updated report
REM Exit codes: 0 = success, 1 = network error, 2 = verification failure

REM Generate filename with date
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /format:list') do set datetime=%%I
set DATESTAMP=%datetime:~0,4%-%datetime:~4,2%-%datetime:~6,2%

REM Set paths
set OUTPUT_DIR=C:\Users\theal\OneDrive\AI_Projects\Travel Advisory
set PROJECT_DIR=C:\Users\theal\Projects\travel-advisory
set OUTPUT_FILE=%OUTPUT_DIR%\travel_advisory_%DATESTAMP%.pdf
set LATEST_FILE=%OUTPUT_DIR%\travel_advisory_report.pdf
set VERIFY_FILE=%OUTPUT_DIR%\travel_advisory_%DATESTAMP%.verification.txt
set LATEST_VERIFY=%OUTPUT_DIR%\travel_advisory_report.verification.txt

REM Log start
echo [%date% %time%] Starting Travel Advisory Report... >> "%OUTPUT_DIR%\run_log.txt"

REM Change to project directory and run
cd /d "%PROJECT_DIR%"
"%PROJECT_DIR%\.venv\Scripts\python.exe" -m travel_advisory.main -o "%OUTPUT_FILE%"
set EXIT_CODE=%ERRORLEVEL%

REM Handle results by exit code
if %EXIT_CODE% EQU 0 (
    copy /Y "%OUTPUT_FILE%" "%LATEST_FILE%" >nul
    if exist "%VERIFY_FILE%" (
        copy /Y "%VERIFY_FILE%" "%LATEST_VERIFY%" >nul
    )
    echo [%date% %time%] SUCCESS: Generated %OUTPUT_FILE% >> "%OUTPUT_DIR%\run_log.txt"
) else if %EXIT_CODE% EQU 2 (
    echo [%date% %time%] VERIFICATION FAILED: Report not generated >> "%OUTPUT_DIR%\run_log.txt"
    if exist "%VERIFY_FILE%" (
        echo --- Verification Details --- >> "%OUTPUT_DIR%\run_log.txt"
        type "%VERIFY_FILE%" >> "%OUTPUT_DIR%\run_log.txt"
        echo --- End Verification --- >> "%OUTPUT_DIR%\run_log.txt"
    )
) else (
    echo [%date% %time%] ERROR: Failed with exit code %EXIT_CODE% >> "%OUTPUT_DIR%\run_log.txt"
)

REM Append verification log to run_log for audit trail
if exist "%VERIFY_FILE%" (
    echo [%date% %time%] Verification log: >> "%OUTPUT_DIR%\run_log.txt"
    type "%VERIFY_FILE%" >> "%OUTPUT_DIR%\run_log.txt"
)
