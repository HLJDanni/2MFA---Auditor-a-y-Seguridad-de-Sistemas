@echo off
chcp 65001 >nul
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo No se encontro Node.js. Instalalo desde https://nodejs.org ^(version LTS^) y vuelve a abrir este archivo.
  echo.
  pause
  exit /b 1
)
echo Instalando dependencias...
call npm install --no-audit --no-fund
if errorlevel 1 (
  echo.
  echo Fallo la instalacion. Revisa tu conexion a internet.
  pause
  exit /b 1
)
echo.
echo Abriendo http://localhost:3000 ...
start "" http://localhost:3000
call npm start
pause
