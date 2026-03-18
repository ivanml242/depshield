@echo off
echo ============================================
echo   depshield - Configuracion automatica
echo ============================================
echo.

REM --- Comprobar que Python existe ---
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] No se encuentra Python.
    echo Descarga Python 3.12 de https://www.python.org/downloads/
    echo IMPORTANTE: Marca "Add python.exe to PATH" al instalar.
    echo Despues de instalar, cierra esta terminal, abre una nueva y ejecuta setup.bat otra vez.
    pause
    exit /b 1
)

REM --- Comprobar version de Python ---
echo [1/5] Comprobando version de Python...
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo       Python %PYVER% detectado.

for /f "tokens=1,2 delims=." %%a in ("%PYVER%") do (
    set PYMAJOR=%%a
    set PYMINOR=%%b
)

if %PYMAJOR% lss 3 (
    echo [ERROR] Se necesita Python 3.11 o superior. Tienes Python %PYVER%.
    echo Descarga Python 3.12 de https://www.python.org/downloads/
    pause
    exit /b 1
)

if %PYMINOR% lss 11 (
    echo [ERROR] Se necesita Python 3.11 o superior. Tienes Python %PYVER%.
    echo Descarga Python 3.12 de https://www.python.org/downloads/
    echo.
    echo Si ya instalaste Python 3.12 pero sigue saliendo la version vieja:
    echo   1. Abre "Variables de entorno" en la configuracion de Windows
    echo   2. En PATH, mueve Python 3.12 por encima de Python %PYVER%
    echo   3. O usa:  py -3.12 -m venv .venv
    pause
    exit /b 1
)

echo       [OK] Version compatible.
echo.

REM --- Borrar venv viejo si existe ---
echo [2/5] Preparando entorno virtual...
if exist .venv (
    echo       Borrando entorno virtual anterior...
    rmdir /s /q .venv
)

REM --- Crear venv nuevo ---
echo       Creando entorno virtual nuevo...
python -m venv .venv
if %errorlevel% neq 0 (
    echo [ERROR] No se pudo crear el entorno virtual.
    echo Prueba manualmente: python -m venv .venv
    pause
    exit /b 1
)
echo       [OK] Entorno virtual creado.
echo.

REM --- Activar venv e instalar ---
echo [3/5] Instalando dependencias (esto puede tardar 1-2 minutos)...
call .venv\Scripts\activate.bat
pip install -e ".[dev]" --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Fallo la instalacion de dependencias.
    echo Prueba manualmente:
    echo   .\.venv\Scripts\Activate.ps1
    echo   pip install -e ".[dev]"
    pause
    exit /b 1
)
echo       [OK] Dependencias instaladas.
echo.

REM --- Verificar imports ---
echo [4/5] Verificando que los imports funcionan...
python -c "import click; print('       click: OK')"
if %errorlevel% neq 0 (
    echo [ERROR] click no se importa correctamente.
    pause
    exit /b 1
)
python -c "from depshield import __version__; print('       depshield: OK (v' + __version__ + ')')"
if %errorlevel% neq 0 (
    echo [ERROR] depshield no se importa correctamente.
    pause
    exit /b 1
)

REM --- Ejecutar tests ---
echo.
echo [5/5] Ejecutando tests...
pytest -v
echo.

echo ============================================
echo   TODO LISTO
echo ============================================
echo.
echo Cada vez que abras una terminal nueva, activa el venv con:
echo   .\.venv\Scripts\Activate.ps1
echo.
echo Para ejecutar depshield:
echo   depshield --version
echo   depshield scan .
echo.
pause
