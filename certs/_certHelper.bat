@echo off
SETLOCAL EnableDelayedExpansion

:: Check if the correct number of arguments is given
IF "%~1"=="" (
    echo Usage: %0 app
    exit /b 1
)

SET "app=%~1"

:: Check if the key file exists
IF NOT EXIST ".\%app%.key" (
    openssl ecparam -genkey -name secp384r1 -out ".\%app%.key"
)

:: Check if the config file exists
IF NOT EXIST ".\%app%.cfg" (
    echo Please create openssl config file for %app%
    exit /b 1
) ELSE (
    echo Please verify the config file for %app% and make sure the following is correct:
    openssl req -new -key ".\%app%.key" -out ".\%app%.req" -config ".\%app%.cfg"
    echo Please generate a new ssl cert with %app%.req and copy %app%.crt in this directory
    echo waiting for %app%.crt

    :: Wait until the .\%app%.crt file exists
    :waitloop
    IF NOT EXIST ".\%app%.crt" (
        timeout /t 1 >nul
        goto waitloop
    )

    openssl x509 -inform der -in ".\%app%.crt" -out ".\%app%.pem"
    echo Congrats, the certificate has been made
)

:: Prompt the user if they wish to clean up the old files
SET /P answer=Do you wish to clean up the old files? (y/n) 
IF /I "!answer!"=="y" (
    del ".\%app%.crt"
    del ".\%app%.req"
    echo Old files have been cleaned up.
) ELSE (
    echo No files have been deleted.
)

ENDLOCAL
