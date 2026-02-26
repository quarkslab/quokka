@echo off

rem Download a specific IDA SDK zip.
rem Usage: fetch_sdk.bat <version>

if "%~1"=="" (
    echo Usage: fetch_sdk.bat ^<version^>
    exit /b 1
)

set "VERSION=%~1"

if not exist "..\third_party" mkdir ..\third_party

set "URL="
if "%VERSION%"=="74"    set "URL=http://files.quarkslab.com/22262c8a-f73c-4571-b7cb-7d2b0abdf8df/idasdk74.zip"
if "%VERSION%"=="77"    set "URL=https://files.quarkslab.com/c6116218-52da-4c7d-b7ad-07a19fd6b075/idasdk77.zip"
if "%VERSION%"=="80"    set "URL=https://files.quarkslab.com/b91adc05-abdc-44ef-a1e2-6a3ccccc4c24/idasdk80.zip"
if "%VERSION%"=="81"    set "URL=https://files.quarkslab.com/cf1c6814-6304-466b-afa7-e02dab13c456/idasdk81.zip"
if "%VERSION%"=="82"    set "URL=https://files.quarkslab.com/96048f23-abb7-4f13-aeda-38ac156cea4e/idasdk82.zip"
if "%VERSION%"=="83"    set "URL=https://files.quarkslab.com/c2c793ae-7a42-4c91-aee7-725547547d3e/idasdk83.zip"
if "%VERSION%"=="84"    set "URL=https://files.quarkslab.com/45f34231-eac9-4b8a-9b39-52237b83515a/idasdk84.zip"
if "%VERSION%"=="85"    set "URL=https://files.quarkslab.com/736e0826-a312-4627-9e6d-d9c747f1d324/idasdk85.zip"
if "%VERSION%"=="90"    set "URL=https://files.quarkslab.com/2fe96720-93f5-46f2-a476-69a0304df901/idasdk90.zip"
if "%VERSION%"=="90sp1" set "URL=https://files.quarkslab.com/4b1d22ac-209e-46f8-bed1-df32a7d772d1/idasdk90sp1.zip"
if "%VERSION%"=="91"    set "URL=https://files.quarkslab.com/f773930b-3c20-4974-992b-472b88223cd9/idasdk91.zip"

if not defined URL (
    echo Unknown SDK version: %VERSION% >&2
    exit /b 1
)

curl -L -o "..\third_party\idasdk%VERSION%.zip" "%URL%"
echo Download complete.
