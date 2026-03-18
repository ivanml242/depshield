# Guia de configuracion del entorno - depshield

**LEEME ENTERO ANTES DE HACER NADA. Sigue los pasos EN ORDEN.**

Este proyecto requiere **Python 3.11 o superior**. Si tienes Python 3.9 o 3.10, NO va a funcionar.
A continuacion te explico como comprobar tu version, instalar la correcta si hace falta, y dejarlo todo listo.

---

## PASO 1: Comprobar que version de Python tienes

Abre una terminal y ejecuta estos tres comandos (los tres, uno por uno):

```bash
python3 --version
```

```bash
python3.11 --version
```

```bash
python3.12 --version
```

**Interpreta los resultados:**

- Si `python3 --version` dice **3.11.x** o **3.12.x** o **3.13.x** -> Perfecto, ya lo tienes. Ve al PASO 2.
- Si `python3.11 --version` o `python3.12 --version` funciona (no dice "command not found") -> Lo tienes instalado pero no es el default. Ve al PASO 2 y usa `python3.11` o `python3.12` en vez de `python3`.
- Si TODOS dicen version 3.9 o 3.10, o dicen "command not found" -> Necesitas instalar Python. Ve al PASO 1b.

---

## PASO 1b: Instalar Python 3.12 (solo si NO lo tienes)

### En macOS (con Homebrew):

Si tienes Homebrew instalado (ejecuta `brew --version` para comprobarlo):

```bash
brew install python@3.12
```

Despues de instalar, comprueba:

```bash
python3.12 --version
```

Deberia decir `Python 3.12.x`.

**Si NO tienes Homebrew**, instalalo primero:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**IMPORTANTE para macOS con chip Apple Silicon (M1/M2/M3):** Despues de instalar Homebrew, la terminal te va a mostrar unas lineas que dicen "Add Homebrew to your PATH". **TIENES QUE EJECUTAR ESAS LINEAS** o Homebrew no funcionara. Normalmente son algo como:

```bash
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

Despues de eso, ejecuta `brew install python@3.12`.

### En Linux (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install python3.12 python3.12-venv python3.12-dev
```

### En Windows:

Descarga el instalador de https://www.python.org/downloads/ (version 3.12.x).
**IMPORTANTE**: En el instalador, marca la casilla **"Add Python to PATH"** antes de darle a Install.

---

## PASO 2: Clonar el repositorio (si no lo tienes ya)

```bash
git clone https://github.com/ivanml242/depshield.git
cd depshield
```

Si ya lo tienes clonado, simplemente entra en la carpeta:

```bash
cd depshield
```

---

## PASO 3: Borrar el entorno virtual viejo (si existe)

Si hay una carpeta `.venv` que se creo con una version vieja de Python, borrala:

```bash
rm -rf .venv
```

Esto no borra nada del proyecto, solo el entorno virtual (que se va a recrear).

---

## PASO 4: Crear el entorno virtual con Python 3.11+

Ejecuta UNO de estos comandos, dependiendo de cual te funcione (el primero que NO de error):

**Opcion A** (si `python3` ya es 3.11+):
```bash
python3 -m venv .venv
```

**Opcion B** (si instalaste Python 3.12 con brew):
```bash
python3.12 -m venv .venv
```

**Opcion C** (si tienes python3.11):
```bash
python3.11 -m venv .venv
```

**Si te da un error tipo "No module named venv":**
- En Linux: `sudo apt install python3.12-venv` y vuelve a intentar
- En macOS con brew: no deberia pasar, pero prueba `brew reinstall python@3.12`

---

## PASO 5: Activar el entorno virtual

**En macOS / Linux:**
```bash
source .venv/bin/activate
```

**En Windows (PowerShell):**
```powershell
.\.venv\Scripts\Activate.ps1
```

**En Windows (cmd):**
```cmd
.\.venv\Scripts\activate.bat
```

**Como saber que funciono:** Tu prompt de terminal deberia mostrar `(.venv)` al principio. Ejemplo:

```
(.venv) usuario@ordenador depshield %
```

Si no ves `(.venv)`, algo salio mal. Vuelve a intentar el comando de activacion.

---

## PASO 6: Instalar el proyecto y sus dependencias

Con el entorno virtual activado (ves `(.venv)` en el prompt), ejecuta:

```bash
pip install -e ".[dev]"
```

Este comando hace tres cosas:
1. Instala las dependencias del proyecto: `requests`, `click`, `rich`, `esprima`
2. Instala las dependencias de desarrollo: `pytest`, `pytest-cov`
3. Instala `depshield` en modo editable (los cambios que hagas al codigo se reflejan al instante)

**Si te dice "pip: command not found":** Prueba con `pip3` en vez de `pip`, o con `python3 -m pip install -e ".[dev]"`.

---

## PASO 7: Verificar que todo funciona

Ejecuta estos comandos uno por uno. **Todos deben funcionar sin errores:**

```bash
python -c "import click; print('click OK')"
```

```bash
python -c "from depshield import __version__; print(f'depshield {__version__} OK')"
```

```bash
depshield --version
```

```bash
pytest -v
```

**Si todo da OK, ya estas listo para trabajar.**

---

## Problemas frecuentes y soluciones

### "import click" sale en rojo en el IDE

Esto pasa porque el IDE no esta usando el Python del entorno virtual. Solucion:

- **VS Code**: Pulsa `Cmd+Shift+P` (macOS) o `Ctrl+Shift+P` (Windows/Linux), escribe "Python: Select Interpreter", y selecciona el que dice `.venv` o `depshield/.venv/bin/python`.
- **PyCharm**: Ve a Settings > Project > Python Interpreter > Add Interpreter > Existing > selecciona `.venv/bin/python`.

### "externally-managed-environment" al hacer pip install

Este error aparece en Python 3.12+ en algunas distros Linux. Solucion: asegurate de que tienes el venv activado (ves `(.venv)` en el prompt) antes de hacer pip install. El error sale cuando intentas instalar en el Python del sistema en vez de en el venv.

### El comando `depshield` no se encuentra despues de instalar

Asegurate de que el venv esta activado (`source .venv/bin/activate`). El comando solo existe dentro del venv.

### "pip install -e ." da error de version de Python

Si el error dice algo como "requires Python >=3.11 but you have 3.9", es que creaste el venv con la version equivocada de Python. Vuelve al PASO 3 (borrar venv) y al PASO 4 (crear con la version correcta).

---

## Resumen rapido (si ya sabes lo que haces)

```bash
git clone https://github.com/ivanml242/depshield.git
cd depshield
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```
