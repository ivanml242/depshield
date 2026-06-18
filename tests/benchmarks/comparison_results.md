# Benchmark: depshield vs GuardDog

> **Auto-generated file** — do not edit manually.
> Re-run with: `pytest -m benchmark -v -s`

## Summary

| Metric | depshield | GuardDog |
|---|---|---|
| True Positives (TP) | 0 | 0 |
| False Negatives (FN) | 7 | 7 |
| True Negatives (TN) | 9 | 10 |
| False Positives (FP) | 1 | 0 |
| **Precision** | **0.00%** | **0.00%** |
| **Recall** | **0.00%** | **0.00%** |
| **F1-Score** | **0.00%** | **0.00%** |
| Avg time/package | 1.10s | 0.03s |
| Total time | 22.06s | 0.57s |

## Detailed results — Malicious packages

| Package | Ecosystem | depshield score | depshield | GuardDog issues | GuardDog |
|---|---|---|---|---|---|
| 029testnpm | npm | 0 (SKIP) | ❌ | 0 | ❌ |
| 0maptrea | npm | 15 (LOW_RISK) | ❌ | 0 | ❌ |
| 0supportscolor | npm | 27 (LOW_RISK) | ❌ | 0 | ❌ |
| --hiljson | npm | 15 (LOW_RISK) | ❌ | 0 | ❌ |
| 0x-fee-wrapper-contract | npm | 2 (SAFE) | ❌ | 0 | ❌ |
| 0-dns | npm | 2 (SAFE) | ❌ | 0 | ❌ |
| 0-shadowenv | npm | 2 (SAFE) | ❌ | 0 | ❌ |
| littest | pypi | N/A (SKIP) | ❌ | N/A | ❌ |
| ab-request | npm | N/A (SKIP) | ❌ | N/A | ❌ |
| abc-to-copy | npm | N/A (SKIP) | ❌ | N/A | ❌ |

## Detailed results — Legitimate packages

| Package | Ecosystem | depshield score | depshield | GuardDog issues | GuardDog |
|---|---|---|---|---|---|
| is-odd | npm | 0 (SAFE) | ✅ | 0 | ✅ |
| minimist | npm | 0 (SAFE) | ✅ | 0 | ✅ |
| color-name | npm | 0 (SAFE) | ✅ | 0 | ✅ |
| ms | npm | 6 (SAFE) | ✅ | 0 | ✅ |
| escape-string-regexp | npm | 1 (SAFE) | ✅ | 0 | ✅ |
| six | pypi | 9 (SAFE) | ✅ | 0 | ✅ |
| click | pypi | 48 (MEDIUM_RISK) | ❌ FP | 0 | ✅ |
| idna | pypi | 1 (SAFE) | ✅ | 0 | ✅ |
| certifi | pypi | 9 (SAFE) | ✅ | 0 | ✅ |
| charset-normalizer | pypi | 9 (SAFE) | ✅ | 0 | ✅ |

## Interpretation

- **Precision**: Of the packages flagged as malicious, how many were actually malicious?
- **Recall**: Of the actually malicious packages, how many were detected?
- **F1-Score**: Harmonic mean of Precision and Recall (overall balance).
- ✅ = correct result, ❌ = incorrect result, ❌ FP = false positive.

## Notes

- Many malicious packages are removed from registries after being reported.
  Packages that could not be downloaded are excluded from the comparison.
- GuardDog is invoked via `python -m guarddog {ecosystem} scan {name}`.
- depshield analyzes both source code (AST) and metadata; GuardDog uses Semgrep rules.
- Times include network latency (download + API calls).
