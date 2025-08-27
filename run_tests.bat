@echo off
setlocal enabledelayedexpansion

rem Path to exe
set EXE=%~1

rem Path to JSON tests
set TEST=%~2

rem Starting file (if provided as argument)
set STARTFILE=%~3
set STARTED=0

if not "!STARTFILE!"=="" (
    echo Starting at !STARTFILE!
)

rem Loop through all JSON files in the current directory
for %%F in (%TEST%*.json) do (

    if "!STARTFILE!"=="" (
        set STARTED=1
    ) else (
        if /i "%%~nxF"=="%STARTFILE%" (
            set STARTED=1
        ) else (
            if !STARTED! == 0 (
                echo Skipping %%~nxF
            )
        )
    )

    if !STARTED! == 1 (
        echo Running %%F...
        %EXE% "%%F"
        set "ERR=!ERRORLEVEL!"
        if not "!ERR!"=="0" (
            echo ERROR: Test %%~nxF failed
            exit /b !ERR!
        )
    )
)

if not "!STARTFILE!"=="" (
    if !STARTED! == 0 (
        echo File not found: !STARTFILE!
    ) else (
        echo All tests passed. from !STARTFILE!
    )
) else (
    echo All tests passed.
)
endlocal