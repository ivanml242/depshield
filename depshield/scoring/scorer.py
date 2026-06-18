"""Risk scoring for analyzed packages.

Takes findings from the analyzers and computes a numeric score (0-100)
with a risk classification. Higher score = more suspicious.

Weights: HIGH +25, MEDIUM +10, LOW +3, TRUST -20.
Brackets: 0-10 SAFE, 11-30 LOW_RISK, 31-60 MEDIUM_RISK, 61+ HIGH_RISK.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from depshield.analyzers.js_analyzer import Finding


# Puntos por severidad

_SEVERITY_WEIGHTS = {
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 3,
    "TRUST": -20,
}

_MAX_SCORE = 100


@dataclass
class PackageScore:
    """Result of scoring a single package."""

    name: str
    version: str
    score: int                       # 0–100
    classification: str              # SAFE / LOW_RISK / MEDIUM_RISK / HIGH_RISK
    findings: list[Finding]          # sorted by severity (HIGH first)
    is_direct: bool = True           # direct dependency vs transitive

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity."""
        result: dict[str, list[Finding]] = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")



def _classify(score: int) -> str:
    """Turn a numeric score into a risk label."""
    if score <= 10:
        return "SAFE"
    if score <= 30:
        return "LOW_RISK"
    if score <= 60:
        return "MEDIUM_RISK"
    return "HIGH_RISK"


def score_package(
    name: str,
    version: str,
    findings: list[Finding],
    *,
    is_direct: bool = True,
) -> PackageScore:
    """Compute the risk score for one package.

    Scoring works in two phases:

    1. **Risk phase**: sum the weights of all non-TRUST findings
       (HIGH +25, MEDIUM +10, LOW +3), capped at 100.
    2. **Trust phase**: each TRUST finding applies a 30 % discount
       to the risk score, compounding multiplicatively.

    Example: a package with 4 HIGH code findings (raw = 100) and
    3 TRUST indicators gets 100 × 0.70³ ≈ 34 → MEDIUM_RISK.
    """
    # Phase 1: risk score from code + metadata findings
    code_findings = [f for f in findings if f.severity != "TRUST"]
    trust_findings = [f for f in findings if f.severity == "TRUST"]

    # Deduplicate for scoring: same signal_type in same file counts once.
    # All findings are still kept in the report for transparency.
    seen: set[tuple[str, str]] = set()
    unique_risk = 0
    for f in code_findings:
        key = (f.signal_type, f.file)
        if key not in seen:
            seen.add(key)
            unique_risk += _SEVERITY_WEIGHTS.get(f.severity, 0)
    capped_risk = min(unique_risk, _MAX_SCORE)

    # Phase 2: trust discount (each TRUST finding = 30% reduction)
    trust_multiplier = 0.70 ** len(trust_findings)
    final_score = int(capped_risk * trust_multiplier)
    final_score = max(final_score, 0)

    # Sort findings by severity: HIGH → MEDIUM → LOW → TRUST
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "TRUST": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 4))

    return PackageScore(
        name=name,
        version=version,
        score=final_score,
        classification=_classify(final_score),
        findings=sorted_findings,
        is_direct=is_direct,
    )


def score_all(
    packages: list[tuple[str, str, list[Finding], bool]],
) -> list[PackageScore]:
    """Score a batch of packages.

    Expects a list of (name, version, findings, is_direct) tuples.
    Returns the results sorted: direct deps first, then by score
    (highest first).
    """
    scores = [
        score_package(name, version, findings, is_direct=is_direct)
        for name, version, findings, is_direct in packages
    ]

    # Sort: direct deps first, then by score descending
    scores.sort(key=lambda s: (not s.is_direct, -s.score))
    return scores
