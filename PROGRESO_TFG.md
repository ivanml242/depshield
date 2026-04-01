# Progreso de Implementación — TFG depshield

> **Autor:** Iván M.  
> **Universidad:** URJC — Grado en Ingeniería en Ciberseguridad  
> **Fecha de inicio:** 18 de marzo de 2026  
> **Última actualización:** 19 de marzo de 2026  
> **Repositorio:** [github.com/ivanml242/depshield](https://github.com/ivanml242/depshield)

---

## 1. Contexto del proyecto

El proyecto **depshield** es una herramienta CLI escrita en Python que analiza las dependencias de un proyecto de software (ecosistemas npm y PyPI) **antes de que el desarrollador ejecute `npm install` o `pip install`**. Su objetivo es detectar paquetes potencialmente maliciosos en toda la cadena de suministro, incluyendo dependencias transitivas.

### Problema que resuelve

Los ataques a la cadena de suministro de software se han duplicado en 2025. Técnicas como el *typosquatting*, *dependency confusion* y cuentas de mantenedores comprometidas permiten a los atacantes publicar paquetes maliciosos en registros públicos como npm y PyPI. Las herramientas existentes tienen carencias importantes:

- **npm audit / pip-audit:** Solo detectan vulnerabilidades conocidas (CVEs). No detectan paquetes maliciosos zero-day.
- **GuardDog (Datadog):** Analiza paquetes individuales con reglas Semgrep, pero no resuelve el árbol transitivo completo y es evasible con ofuscación básica.
- **Packj:** Audita paquetes uno a uno, no el proyecto completo. Requiere Linux.
- **Socket.dev:** Comercial y de código cerrado.

Ninguna herramienta existente combina: (1) resolución del árbol transitivo completo, (2) análisis estático comportamental del código fuente, (3) análisis de metadatos sospechosos, y (4) un modelo de scoring multi-señal.

### Arquitectura general

```
[package.json / requirements.txt]
            │
            ▼
   ┌─────────────────┐
   │   RESOLVERS      │  ← Consulta APIs gratuitas de npm/PyPI
   │  npm + pypi      │     Construye árbol transitivo de deps
   └────────┬─────────┘
            │
            ▼
   ┌─────────────────┐
   │   DOWNLOADER     │  ← Descarga código fuente (.tar.gz)
   │                  │     Extrae en directorio temporal
   └────────┬─────────┘
            │
            ▼
   ┌─────────────────┐
   │   ANALYZERS      │  ← 3 analizadores en paralelo:
   │  js + py + meta  │     - Estático JS (esprima AST)
   └────────┬─────────┘     - Estático Python (ast stdlib)
            │                - Metadatos (API registros)
            ▼
   ┌─────────────────┐
   │   SCORER         │  ← Pondera hallazgos por severidad
   │                  │     Clasifica: SAFE/LOW/MEDIUM/HIGH
   └────────┬─────────┘
            │
            ▼
   ┌─────────────────┐
   │   REPORT         │  ← Tabla en terminal (rich)
   │  table + json    │     + export JSON
   └──────────────────┘
```

### Stack técnico

| Componente | Tecnología |
|---|---|
| Lenguaje | Python 3.12 |
| CLI | click |
| Parsing JS | esprima (port Python) + fallback regex |
| Parsing Python | ast (módulo built-in) |
| HTTP | requests |
| Output terminal | rich (tablas con colores) |
| Testing | pytest + pytest-cov |
| APIs | registry.npmjs.org (gratis) y pypi.org/pypi/ (gratis) |
| Dataset validación | OpenSSF malicious-packages (+15.000 reportes OSV) |
| Benchmark | Comparativa directa con GuardDog |

---

## 2. Plan de implementación (12 pasos)

El desarrollo se estructura en 12 pasos secuenciales (PASO 0 a PASO 11), donde cada paso produce un módulo funcional, testeado e integrado con el anterior:

| Paso | Módulo | Descripción |
|---|---|---|
| 0 | Proyecto base | Estructura, pyproject.toml, CLI stub, git |
| 1 | npm resolver | Árbol transitivo de dependencias npm |
| 2 | PyPI resolver | Árbol transitivo de dependencias PyPI |
| 3 | Downloader | Descarga y extracción de código fuente |
| 4 | JS analyzer | Análisis estático AST de JavaScript |
| 5 | Python analyzer | Análisis estático AST de Python |
| 6 | Metadata analyzer | Análisis de metadatos sospechosos |
| 7 | Scorer + Report | Motor de puntuación y generación de informes |
| 8 | Scanner + CLI | Orquestador principal, caché, CLI completa |
| 9 | Tests integración | Validación contra paquetes maliciosos reales |
| 10 | Benchmark | Comparativa con GuardDog |
| 11 | Documentación | README, ARCHITECTURE.md, pulido final |

---

## 3. PASO 0 — Configuración del proyecto

**Objetivo:** Crear la estructura base del proyecto Python, configurar las dependencias, definir el punto de entrada de la CLI, e inicializar el control de versiones.

### 3.1. Estructura de directorios creada

```
depshield/
├── depshield/
│   ├── __init__.py          # Paquete principal, define __version__
│   └── cli.py               # Interfaz CLI con click
├── tests/
│   └── __init__.py
├── .venv/                   # Entorno virtual Python (no versionado)
├── .gitignore
├── pyproject.toml           # Configuración del proyecto (PEP 621)
└── README.md
```

### 3.2. Configuración del proyecto — `pyproject.toml`

Se utilizó el estándar **PEP 621** con `setuptools` como sistema de build, evitando herramientas como Poetry para mantener la simplicidad:

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "depshield"
version = "0.1.0"
requires-python = ">=3.11"

dependencies = [
    "requests",
    "click",
    "rich",
    "esprima",
]

[project.optional-dependencies]
dev = [
    "pytest",
    "pytest-cov",
]

[project.scripts]
depshield = "depshield.cli:main"
```

El campo `[project.scripts]` define el punto de entrada CLI: al instalar el paquete, se crea un ejecutable `depshield` que invoca la función `main()` de `depshield/cli.py`.

### 3.3. CLI inicial — `depshield/cli.py`

Se implementó un esqueleto funcional de la CLI usando **click** con la estructura de comandos que se irá completando en pasos posteriores:

```python
@click.group()
@click.version_option(version=__version__, prog_name="depshield")
def main():
    """depshield - Detect malicious dependencies before installation."""

@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option("--ecosystem", type=click.Choice(["npm", "pypi", "auto"]), default="auto")
@click.option("--no-cache", is_flag=True, default=False)
@click.option("--max-depth", type=int, default=3)
@click.option("--only-direct", is_flag=True, default=False)
def scan(path, output_format, ecosystem, no_cache, max_depth, only_direct):
    """Scan a project directory for malicious dependencies."""
    click.echo(f"depshield v{__version__}")
    click.echo(f"Scanning: {path}")
```

### 3.4. Entorno de desarrollo

Se creó un entorno virtual de Python y se instaló el proyecto en modo editable para desarrollo:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

La instalación en modo editable (`-e`) permite que los cambios en el código fuente se reflejen inmediatamente sin necesidad de reinstalar. Las dependencias de desarrollo (`[dev]`) incluyen `pytest` y `pytest-cov`.

### 3.5. Verificación

```powershell
# Verificar que la CLI funciona
depshield --version        # → depshield, version 0.1.0
depshield scan .           # → Output de stub
depshield scan --help      # → Muestra todas las opciones

# Verificar que pytest funciona
pytest -v                  # → 0 tests (esperado en este paso)
```

### 3.6. Control de versiones

```powershell
git init
git add .
git commit -m "PASO 0: Initial project setup"
git remote add origin https://github.com/ivanml242/depshield.git
git branch -M main
git push -u origin main
```

---

## 4. PASO 1 — Resolución de dependencias npm

**Objetivo:** Crear un módulo capaz de leer un fichero `package.json`, consultar la API pública de npm, resolver las versiones según las restricciones semver, y construir el árbol completo de dependencias transitivas de forma recursiva.

### 4.1. Módulo creado: `depshield/resolvers/npm_resolver.py`

Se creó el subpaquete `depshield/resolvers/` con los ficheros:

```
depshield/resolvers/
├── __init__.py
└── npm_resolver.py
```

### 4.2. Modelo de datos — `DependencyNode`

Se definió una estructura de datos reutilizable (dataclass) que representa un nodo en el árbol de dependencias. Esta misma estructura será compartida por el resolver de PyPI en el PASO 2:

```python
@dataclass
class DependencyNode:
    name: str                                    # Nombre del paquete
    version: str                                 # Versión resuelta
    is_direct: bool = False                      # ¿Es dependencia directa del proyecto?
    children: list["DependencyNode"] = field(default_factory=list)  # Dependencias transitivas

    def flatten(self) -> list["DependencyNode"]:
        """Devuelve una lista plana de este nodo + todos sus descendientes."""
        result = [self]
        for child in self.children:
            result.extend(child.flatten())
        return result
```

### 4.3. Resolución semver

Se implementó un resolutor de semver básico pero funcional que cubre los formatos más comunes encontrados en el ecosistema npm:

| Formato | Ejemplo | Comportamiento |
|---|---|---|
| Exact | `1.2.3` | Coincidencia exacta |
| Caret (`^`) | `^1.2.3` | Permite cambios que no modifiquen el dígito más a la izquierda distinto de cero. Ej: `^1.2.3` acepta `>=1.2.3, <2.0.0` |
| Tilde (`~`) | `~1.2.3` | Permite cambios a nivel de patch. Ej: `~1.2.3` acepta `>=1.2.3, <1.3.0` |
| Greater-equal (`>=`) | `>=1.0.0` | Cualquier versión superior o igual |
| Rango | `>=1.0.0 <2.0.0` | Versiones dentro del rango especificado |
| OR (`\|\|`) | `^1 \|\| ^2` | Evalúa cada rama y devuelve la primera que produzca un match |
| Star/Latest | `*` o `latest` | Selecciona la versión estable más reciente |

La función `_best_match(versions, spec)` recibe la lista completa de versiones disponibles de un paquete y la especificación semver, y devuelve la versión más alta que satisface la restricción. Las versiones pre-release se filtran por defecto.

### 4.4. Cliente de la API de npm

Se implementó un cliente HTTP que consulta la API pública del registro de npm:

```
GET https://registry.npmjs.org/{package_name}
```

Este endpoint devuelve toda la metadata del paquete, incluyendo un campo `versions` que contiene, para cada versión publicada, sus propias dependencias en el campo `dependencies`.

Se implementó **rate limiting** para respetar los límites de la API (máximo ~1000 requests/hora):

```python
def _rate_limit() -> None:
    """Asegura al menos 1 segundo entre peticiones HTTP consecutivas."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < 1.0:
        time.sleep(1.0 - elapsed)
    _last_request_time = time.time()
```

### 4.5. Resolución recursiva del árbol

La función principal `resolve_tree()` construye el árbol de dependencias de forma recursiva:

```python
def resolve_tree(
    deps: dict[str, str],       # {"chalk": "^4.0.0", "minimist": "^1.2.0"}
    *,
    max_depth: int = 3,         # Profundidad máxima para evitar árboles enormes
    _visited: set[str] = None,  # Control de ciclos: "name@version" ya resueltos
    _depth: int = 0,            # Profundidad actual
    _is_direct: bool = True,    # ¿Nivel de dependencias directas?
) -> list[DependencyNode]:
```

**Algoritmo:**
1. Para cada dependencia en el diccionario de entrada:
   a. Consulta la API de npm para obtener todas las versiones disponibles.
   b. Usa `_best_match()` para resolver la versión que satisface la especificación semver.
   c. Comprueba si `name@version` ya está en el conjunto `_visited` (protección contra ciclos).
   d. Si no se ha visitado y la profundidad actual es menor que `max_depth`, extrae las dependencias transitivas del manifiesto de la versión resuelta y llama recursivamente a `resolve_tree()`.
2. Devuelve la lista de `DependencyNode` con sus hijos populados.

**Protección contra ciclos:** Se mantiene un conjunto global `_visited` con claves `"name@version"`. Si un paquete ya ha sido visitado, se añade como nodo hoja sin resolver sus hijos, evitando recursión infinita.

### 4.6. API pública del módulo

```python
# Lectura de package.json
def read_package_json(path) -> dict[str, str]:
    """Lee package.json y devuelve las dependencias + devDependencies fusionadas."""

# Resolución desde diccionario
def resolve_tree(deps, *, max_depth=3) -> list[DependencyNode]:
    """Resuelve recursivamente el árbol de dependencias."""

# Helper de alto nivel
def resolve_from_package_json(path, *, max_depth=3) -> list[DependencyNode]:
    """Lee package.json y resuelve el árbol completo en un solo paso."""
```

### 4.7. Verificación

Se crearon 19 tests unitarios y de integración que cubrieron:

| Categoría | Tests | Descripción |
|---|---|---|
| Semver | 11 | Exact, caret, tilde, gte, star, latest, OR, range, edge cases |
| package.json | 2 | Lectura con/sin devDependencies |
| DependencyNode | 2 | flatten(), repr() |
| Integración (red) | 4 | Resolución real de `minimist` (0 deps), `chalk` (deps transitivas), ciclos, end-to-end |

**Resultado:** 19/19 PASSED en 5.39 segundos.

Tras la verificación, los tests se eliminaron para mantener el proyecto limpio según las instrucciones del plan.

### 4.8. Commit

```powershell
git add .
git commit -m "PASO 1: npm dependency resolver with semver, rate limiting and cycle protection"
git push origin main
```

---

## 5. PASO 2 — Resolución de dependencias PyPI

**Objetivo:** Crear un módulo análogo al npm resolver, pero para el ecosistema Python. Debe ser capaz de leer un fichero `requirements.txt`, consultar la API pública de PyPI, parsear el campo `requires_dist` de cada paquete para determinar sus dependencias transitivas, y construir el árbol completo de forma recursiva.

### 5.1. Módulo creado: `depshield/resolvers/pypi_resolver.py`

Se añadió al subpaquete `depshield/resolvers/`:

```
depshield/resolvers/
├── __init__.py
├── npm_resolver.py       # ✅ PASO 1
└── pypi_resolver.py      # ✅ PASO 2
```

Se reutiliza el modelo de datos `DependencyNode` definido en el PASO 1 (`npm_resolver.py`), garantizando una interfaz uniforme entre ambos resolvers. Esto permite que los módulos posteriores (downloader, analyzers, scorer) trabajen con la misma estructura de datos independientemente del ecosistema.

### 5.2. Parser de `requirements.txt`

El fichero `requirements.txt` es el estándar de facto para declarar dependencias en proyectos Python. A diferencia de `package.json` (que es JSON estructurado), `requirements.txt` es un fichero de texto plano con una sintaxis más libre y variable. Se implementó un parser basado en expresiones regulares que soporta los formatos más comunes:

| Formato | Ejemplo | Interpretación |
|---|---|---|
| Nombre sin versión | `requests` | Se resolverá a la última versión estable |
| Pinned (fija) | `requests==2.31.0` | Versión exacta |
| Mínima | `requests>=2.20` | Cualquier versión ≥ 2.20 |
| Compatible release | `flask~=2.3` | Equivale a `>=2.3, ==2.*` (mismo major) |
| Comentarios | `# esto es un comentario` | Se ignoran |
| Flags de pip | `-e .` o `--index-url ...` | Se ignoran (líneas que empiezan con `-`) |

```python
_REQ_LINE_RE = re.compile(
    r"""
    ^
    \s*
    (?P<name>[A-Za-z0-9_][A-Za-z0-9._-]*)   # nombre del paquete
    \s*
    (?:
        (?P<op>~=|==|!=|>=|<=|>|<)           # operador de versión
        \s*
        (?P<version>[^\s;#,]+)               # string de versión
    )?
    """,
    re.VERBOSE,
)
```

### 5.3. API de PyPI

A diferencia de npm (que devuelve todo el catálogo de versiones en una sola petición), la API JSON de PyPI ofrece dos endpoints relevantes:

```
# Metadata general del paquete (incluye lista de todas las versiones publicadas)
GET https://pypi.org/pypi/{nombre}/json

# Metadata de una versión específica (incluye requires_dist con las dependencias)
GET https://pypi.org/pypi/{nombre}/{version}/json
```

Esto tiene una implicación directa en el rendimiento: para cada paquete se necesitan **dos peticiones HTTP** (una para conocer las versiones disponibles y otra para obtener las dependencias de la versión resuelta). En npm bastaba con una sola petición porque el campo `versions` del endpoint general ya incluye las dependencias de cada versión.

Se implementó el mismo mecanismo de **rate limiting** (1 segundo entre peticiones) del PASO 1 para respetar los límites de las APIs públicas.

### 5.4. Parser de `requires_dist`

El campo `requires_dist` de la API de PyPI es una lista de strings que describe las dependencias de un paquete. Su formato varía significativamente entre paquetes y versiones, lo que supuso el mayor reto técnico de este paso. Ejemplos reales encontrados:

```python
# Formato con paréntesis (paquetes antiguos)
"urllib3 (>=1.21.1,<3)"

# Formato sin paréntesis (paquetes modernos, ej. requests 2.33+)
"charset_normalizer<4,>=2"

# Dependencia opcional (extra) – debe ser IGNORADA
'PySocks (!=1.5.7,>=1.5.6) ; extra == "socks"'

# Dependencia sin versión
"certifi"
```

La regex del parser tuvo que actualizarse durante el desarrollo para soportar ambas variantes (con y sin paréntesis), ya que la primera versión solo manejaba el formato con paréntesis y fallaba al resolver las dependencias de paquetes como `requests@2.33.1`:

```python
_REQUIRES_DIST_RE = re.compile(
    r"""
    ^
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
    \s*
    (?:
        \((?P<version_paren>[^)]*)\)                    # con paréntesis
        |
        (?P<version_bare>(?:[<>=!~]+[^;,\s]+           # sin paréntesis
            (?:\s*,\s*[<>=!~]+[^;,\s]+)*))
    )?
    (?:\s*;\s*(?P<marker>.*))?                          # marcadores de entorno
    $
    """,
    re.VERBOSE,
)
```

Las dependencias con marcadores de tipo `extra == "..."` se descartan porque representan dependencias opcionales que no se instalan por defecto (ej. `requests[socks]` instala `PySocks`, pero `pip install requests` a secas no lo hace).

### 5.5. Resolución de versiones

El ecosistema PyPI utiliza PEP 440 para la especificación de versiones, que difiere de semver (usado en npm). Se implementó un resolutor que cubre los operadores más frecuentes:

| Operador | Ejemplo | Significado |
|---|---|---|
| `==` | `==2.31.0` | Versión exacta |
| `!=` | `!=1.5.7` | Excluir una versión concreta |
| `>=` | `>=2.20` | Mínimo |
| `<=` | `<=3.0` | Máximo |
| `>` | `>1.0` | Estrictamente mayor |
| `<` | `<4.0` | Estrictamente menor |
| `~=` | `~=2.3` | Compatible release: `>=2.3, ==2.*` |
| Compuesto | `>=1.0,<2.0` | Múltiples restricciones separadas por coma |

A diferencia del PASO 1 (donde el resolutor se implementó en una sola función `_best_match()`), aquí se separó la lógica en dos funciones para manejar la complejidad de los especificadores compuestos:

- `_version_matches_single(version, spec)` → evalúa un solo operador.
- `_resolve_version(versions, spec)` → maneja especificadores compuestos (con coma), llamando a `_version_matches_single()` para cada parte.

### 5.6. Resolución recursiva del árbol

La función `resolve_tree()` sigue el mismo patrón que el PASO 1, con una diferencia clave: la **profundidad máxima por defecto es 5** (en lugar de 3 en npm). Esto se debe a que los árboles de dependencias en PyPI tienden a ser más profundos pero más estrechos que en npm.

```python
def resolve_tree(
    deps: dict[str, str],       # {"requests": ">=2.20", "six": ""}
    *,
    max_depth: int = 5,         # Mayor profundidad que npm (árboles más profundos)
    _visited: set[str] = None,  # Control de ciclos
    _depth: int = 0,
    _is_direct: bool = True,
) -> list[DependencyNode]:
```

**Algoritmo:**
1. Para cada dependencia en el diccionario de entrada:
   a. Primera petición HTTP: obtener todas las versiones disponibles del paquete (`GET /pypi/{name}/json` → campo `releases`).
   b. Aplicar `_resolve_version()` para seleccionar la versión que satisface el especificador.
   c. Comprobar el conjunto `_visited` (protección contra ciclos, idéntica al PASO 1).
   d. Segunda petición HTTP: obtener la metadata de la versión resuelta (`GET /pypi/{name}/{version}/json` → campo `info.requires_dist`).
   e. Parsear `requires_dist` con `_parse_requires_dist()`, descartando dependencias opcionales.
   f. Llamar recursivamente a `resolve_tree()` con las dependencias extraídas.
2. Devolver la lista de `DependencyNode` con hijos populados.

### 5.7. Diferencias clave entre el resolver npm y PyPI

| Aspecto | npm (PASO 1) | PyPI (PASO 2) |
|---|---|---|
| Fichero de entrada | `package.json` (JSON) | `requirements.txt` (texto plano) |
| API de registro | `registry.npmjs.org` | `pypi.org/pypi/` |
| Peticiones por paquete | 1 (todo en un endpoint) | 2 (versiones + metadata de versión) |
| Formato de versiones | semver (`^`, `~`, `*`, `\|\|`) | PEP 440 (`==`, `>=`, `~=`, compuestos) |
| Profundidad por defecto | 3 | 5 |
| Dependencias opcionales | No aplica | `requires_dist` con `extra ==` → se descartan |
| Modelo de datos | `DependencyNode` | `DependencyNode` (compartido) |

### 5.8. API pública del módulo

```python
# Lectura de requirements.txt
def read_requirements_txt(path) -> dict[str, str]:
    """Parsea requirements.txt y devuelve {nombre: especificador_version}."""

# Resolución desde diccionario
def resolve_tree(deps, *, max_depth=5) -> list[DependencyNode]:
    """Resuelve recursivamente el árbol de dependencias PyPI."""

# Helper de alto nivel
def resolve_from_requirements_txt(path, *, max_depth=5) -> list[DependencyNode]:
    """Lee requirements.txt y resuelve el árbol completo en un solo paso."""
```

### 5.9. Verificación

Se crearon 20 tests unitarios y de integración:

| Categoría | Tests | Descripción |
|---|---|---|
| requirements.txt | 4 | Pinned, bare name, comentarios/blancos, compatible release |
| requires_dist | 4 | Con paréntesis, sin paréntesis, filtrado de extras, lista vacía |
| Resolución versiones | 8 | Exact, gte, latest, compatible, compound, not-equal, gt, lt |
| Integración (red) | 4 | `six` (0 deps), `requests` (deps transitivas), ciclos, end-to-end |

**Resultado:** 20/20 PASSED en 11.31 segundos.

El test de `requests` fue especialmente revelador: en la primera ejecución falló porque `requests@2.33.1` usa el formato `requires_dist` sin paréntesis, lo que obligó a actualizar la regex del parser para soportar ambas variantes. Este tipo de incompatibilidad en el formato de los metadatos es un ejemplo real de las dificultades de trabajar con registros de paquetes públicos.

### 5.10. Commit

```powershell
git add .
git commit -m "PASO 2: PyPI dependency resolver with requires_dist parsing and cycle protection"
git push origin main
```

---

## 6. Estado actual del proyecto

> **Última actualización:** 1 de abril de 2026

### Estructura de ficheros

```
depshield/
├── depshield/
│   ├── __init__.py               # v0.1.0
│   ├── cli.py                    # CLI con click (scan stub)
│   └── resolvers/
│       ├── __init__.py
│       ├── npm_resolver.py       # ✅ PASO 1
│       └── pypi_resolver.py      # ✅ PASO 2
├── tests/
│   └── __init__.py
├── .venv/                        # Entorno virtual
├── .gitignore
├── pyproject.toml
├── README.md
├── SETUP.md                      # Guía de configuración del entorno
└── setup.bat                     # Script de configuración automática
```

### Próximos pasos

| Paso | Módulo | Estado |
|---|---|---|
| ~~0~~ | ~~Proyecto base~~ | ✅ Completado |
| ~~1~~ | ~~npm resolver~~ | ✅ Completado |
| ~~2~~ | ~~PyPI resolver~~ | ✅ Completado |
| **3** | **Downloader** | ⏳ Pendiente |
| 4 | JS analyzer | ⏳ Pendiente |
| 5 | Python analyzer | ⏳ Pendiente |
| 6 | Metadata analyzer | ⏳ Pendiente |
| 7 | Scorer + Report | ⏳ Pendiente |
| 8 | Scanner + CLI | ⏳ Pendiente |
| 9 | Tests integración | ⏳ Pendiente |
| 10 | Benchmark vs GuardDog | ⏳ Pendiente |
| 11 | Documentación final | ⏳ Pendiente |
