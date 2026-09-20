"""
Assertion tests for fuzzy_entity_match. Run directly:

    .venv\\Scripts\\python.exe forensic_platform\\tests_engine\\test_fuzzy_entity_match.py

The variant set is SYNTHETIC. It reproduces the shape of a real 13-variant group
observed in practitioner-registration data - word reordering, lost spacing, a
run-together honorific, single-letter typos and an initials-only form - without
carrying any real person's name into the codebase.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from forensic_platform.tests_engine.fuzzy_entity_match import (  # noqa: E402
    DEFAULT_THRESHOLD, canonical, canonical_flat, cluster_names, name_similarity, similarity,
)

# Synthetic: 13 spellings of one fictional practitioner.
VARIANTS = [
    "DR ANUPAM KUMAR BHARGAVA", "ANUPAM KUMAR BHARGAVA", "ANUPAM KUMAR",
    "DR ANUPAM KUMAR", "DR A K BHARGAVA", "DR BHARGAVA ANUPAM KUMAR",
    "BHARGAVA ANUPAM KUMAR", "DR ANUPAM KUMAR BHARGAAVA",
    "DR ANUPAM KUMARBHARGAVA", "ANUPAM BHARGAVA", "DR ANUPAM KUKMAR BHARGAVA",
    "DR ANUPAM KUMAR BHARGEVA", "DR ANUPAM KUMAR BHAGVA",
]

DISTINCT_PEOPLE = ["RAJESH KUMAR SINGH", "SUNITA DEVI", "MOHAMMED ASLAM KHAN"]

failures = 0


def check(label, condition, detail=""):
    global failures
    status = "PASS" if condition else "FAIL"
    if not condition:
        failures += 1
    print(f"  [{status}] {label}{(' - ' + detail) if detail else ''}")


print("=== canonicalisation ===")
check("honorific stripped + token-sorted",
      canonical("DR ANUPAM KUMAR BHARGAVA") == canonical("BHARGAVA ANUPAM KUMAR"),
      f"{canonical('DR ANUPAM KUMAR BHARGAVA')!r}")
check("spacing collapsed (flat form)",
      canonical_flat("ANUPAMKUMARBHARGAVA") == canonical_flat("ANUPAM KUMAR BHARGAVA"))
check("de-spaced name matches exactly",
      name_similarity("ANUPAMKUMARBHARGAVA", "ANUPAM KUMAR BHARGAVA") == 1.0)
check("run-together honorific still matches",
      name_similarity("DRANUPAM KUMAR BHARGAVA", "DR ANUPAM KUMAR BHARGAVA") >= DEFAULT_THRESHOLD,
      f"sim={name_similarity('DRANUPAM KUMAR BHARGAVA', 'DR ANUPAM KUMAR BHARGAVA'):.3f}")

print("\n=== similarity ===")
check("identical -> 1.0", similarity(canonical("A B"), canonical("A B")) == 1.0)
check("single typo scores high",
      similarity(canonical("DR ANUPAM KUKMAR BHARGAVA"),
                 canonical("ANUPAM KUMAR BHARGAVA")) >= DEFAULT_THRESHOLD)
check("unrelated names score low",
      similarity(canonical("RAJESH KUMAR SINGH"), canonical("SUNITA DEVI")) < DEFAULT_THRESHOLD)

print("\n=== clustering ===")
clusters = cluster_names(VARIANTS, DEFAULT_THRESHOLD)
sizes = sorted((len(c) for c in clusters), reverse=True)
print(f"  13 raw variants -> {len(clusters)} cluster(s), sizes={sizes}")
for c in clusters:
    print(f"    - {c}")
check("collapses 13 variants to a small number of entities", len(clusters) <= 3,
      f"got {len(clusters)}")
check("largest cluster holds the main spelling group", max(sizes) >= 8, f"max={max(sizes)}")
check("initials-only form stays separate (documented limitation)",
      ["DR A K BHARGAVA"] in clusters)

distinct_clusters = cluster_names(DISTINCT_PEOPLE, DEFAULT_THRESHOLD)
check("three genuinely different names stay separate", len(distinct_clusters) == 3,
      f"got {len(distinct_clusters)}")

print("\n=== determinism ===")
a = cluster_names(VARIANTS, DEFAULT_THRESHOLD)
b = cluster_names(list(reversed(VARIANTS)), DEFAULT_THRESHOLD)
check("clustering is order-independent", a == b)

print("\n" + ("ALL TESTS PASS" if failures == 0 else f"{failures} TEST(S) FAILED"))
sys.exit(1 if failures else 0)
