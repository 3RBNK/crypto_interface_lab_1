@echo off
setlocal
pushd "%~dp0"
if errorlevel 1 exit /b 1

where cl >nul 2>nul
if errorlevel 1 (
    echo Open Developer Command Prompt for Visual Studio and run this script again.
    goto :fail
)
if not exist build mkdir build
if not exist build goto :fail

cl /nologo /W4 /utf-8 /std:c11 /Fobuild\ /Febuild\crypto_fixed.exe main.c encrypt.c decrypt.c keygen.c utils.c /link bcrypt.lib
if errorlevel 1 goto :fail

cl /nologo /W4 /utf-8 /std:c11 /I. /Fobuild\ /Febuild\cfb128_test.exe tests\cfb128_test.c utils.c /link bcrypt.lib
if errorlevel 1 goto :fail
build\cfb128_test.exe
if errorlevel 1 goto :fail

build\crypto_fixed.exe decrypt CFB secret_key.bin enc_cfb.bin enc_cfb_iv.bin build\decrypted_cfb.txt
if errorlevel 1 goto :fail
fc /b build\decrypted_cfb.txt result2.txt
if errorlevel 1 goto :fail

echo Build and tests passed. Executable: build\crypto_fixed.exe
popd
exit /b 0

:fail
echo Build or tests failed. See the error above.
popd
exit /b 1
