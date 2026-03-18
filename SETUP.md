# Guia de configuracion del entorno - depshield (Windows)

**LEEME ENTERO ANTES DE HACER NADA. Sigue los pasos EN ORDEN.**

Este proyecto requiere **Python 3.11 o superior**.

---

## PASO 1: Comprobar si tienes Python 3.11+

Abre **PowerShell** (busca "PowerShell" en el menu de inicio) y ejecuta:

```powershell
python --version
```

**Resultados posibles:**

- Dice **Python 3.11.x**, **3.12.x** o **3.13.x** -> Perfecto, salta al PASO 3.
- Dice **Python 3.9.x** o **3.10.x** -> Necesitas instalar una version nueva. Ve al PASO 2.
- Dice **"command not found"** o abre la Microsoft Store -> No tienes Python. Ve al PASO 2.

---

## PASO 2: Instalar Python 3.12 (solo si NO tienes 3.11+)

1. Abre este enlace en tu navegador:

   **https://www.python.org/downloads/**

2. Descarga el instalador de **Python 3.12.x** (el boton amarillo grande).

3. Ejecuta el instalador. **EN LA PRIMERA PANTALLA**, ANTES de darle a Install:

   **MARCA LA CASILLA "Add python.exe to PATH"** (abajo del todo).

   Si no marcas esa casilla, nada va a funcionar despues.

4. Dale a **"Install Now"**.

5. Cuando termine, **CIERRA PowerShell y abre uno nuevo** (esto es importante para que el PATH se actualice).

6. Comprueba que funciono:

```powershell
python --version
```

Debe decir `Python 3.12.x`. Si sigue diciendo 3.9 o 3.10, ve a la seccion de problemas al final.

---

## PASO 3: Clonar el repositorio

Si ya lo tienes clonado, salta al PASO 4.

```powershell
git clone https://github.com/ivanml242/depshield.git
cd depshield
```

Si no tienes git, descargalo de https://git-scm.com/download/win e instalalo con las opciones por defecto.

---

## PASO 4: Configuracion automatica

He preparado un script que hace todo automaticamente. Ejecuta:

```powershell
.\setup.bat
```

Esto va a:
1. Borrar el entorno virtual viejo si existe
2. Crear uno nuevo con tu Python
3. Instalar todas las dependencias
4. Verificar que todo funciona

**Si el script funciona sin errores, ya estas listo. Puedes ir directamente a "Como trabajar en el dia a dia".**

Si el script falla o prefieres hacerlo a mano, sigue con el PASO 5.

---

## PASO 5 (manual, solo si el script fallo): Configurar a mano

### 5a. Borrar entorno virtual viejo (si existe la carpeta .venv):

```powershell
Remove-Item -Recurse -Force .venv
```

### 5b. Crear entorno virtual nuevo:

```powershell
python -m venv .venv
```

### 5c. Activar el entorno virtual:

```powershell
.\.venv\Scripts\Activate.ps1
```

**Si te da un error de "execution policy"**, ejecuta esto primero y luego repite el comando de arriba:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Como saber que funciono:** Debes ver `(.venv)` al inicio del prompt:

```
(.venv) PS C:\Users\tuusuario\depshield>
```

### 5d. Instalar dependencias:

```powershell
pip install -e ".[dev]"
```

### 5e. Verificar:

```powershell
python -c "import click; print('click OK')"
python -c "from depshield import __version__; print('depshield OK')"
depshield --version
pytest -v
```

Si los 4 comandos funcionan, todo esta listo.

---

## Como trabajar en el dia a dia

**Cada vez que abras una terminal nueva** para trabajar en el proyecto, tienes que activar el entorno virtual:

```powershell
cd depshield
.\.venv\Scripts\Activate.ps1
```

Sin activar el venv, los imports no funcionan y `depshield` no se encuentra.

---

## Problemas frecuentes

### "import click" o "from depshield import ..." sale en rojo en el IDE

El IDE no esta usando el Python del entorno virtual.

**Si usas VS Code:**
1. Pulsa `Ctrl+Shift+P`
2. Escribe "Python: Select Interpreter"
3. Selecciona el que dice `.venv` o `depshield\.venv\Scripts\python.exe`

**Si usas PyCharm:**
1. Ve a File > Settings > Project > Python Interpreter
2. Click en el engranaje > Add > Existing Environment
3. Busca `.venv\Scripts\python.exe`

### `python --version` sigue diciendo 3.9 despues de instalar 3.12

Windows tiene varias versiones de Python y usa la primera que encuentra en el PATH. Soluciones:

1. **Opcion rapida:** Usa `py -3.12` en vez de `python`:
   ```powershell
   py -3.12 -m venv .venv
   ```

2. **Opcion definitiva:** Abre "Configuracion del sistema" > busca "Variables de entorno" > en la variable PATH, mueve la ruta de Python 3.12 ARRIBA de la de Python 3.9.

### Error "execution policy" al activar el venv

Ejecuta esto una sola vez:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Se abre la Microsoft Store al escribir `python`

Windows tiene un alias que redirige a la Store. Para quitarlo:
1. Abre Configuracion > Aplicaciones > Alias de ejecucion de aplicaciones
2. Desactiva los alias de "python.exe" y "python3.exe"

### "pip install -e ." dice "requires Python >=3.11"

Creaste el venv con Python 3.9/3.10. Borra el venv y crealo de nuevo:
```powershell
Remove-Item -Recurse -Force .venv
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```
