#!/usr/bin/env python3
"""Runner für die adversarialen Tests.

Findet alle AttackTest-Unterklassen in Adversarial/tests/ und führt jede gegen
jede Variante (Baseline und gehärtet) aus. Pro Test/Variante wird berichtet, was
passiert ist — es gibt keinen Soll-/Ist-Vergleich. Die Interpretation (Baseline
verwundbar, gehärtet blockiert) liest die Auswertung ab.

Aufruf:
    python3 Adversarial/runner.py                       # alle Tests, beide Varianten
    python3 Adversarial/runner.py --variant baseline    # nur Baseline
    python3 Adversarial/runner.py --test php-account-takeover
    python3 Adversarial/runner.py --keep                # Cleanup auslassen (Debug)

Outcomes:
    vulnerable  Angriff durchgelaufen, Backdoor erreichbar
    blocked     Angriffsaktion verhindert oder Backdoor nicht erreichbar
    skipped     Variante nicht erreichbar / nicht implementiert
    error       unerwarteter Fehler in der Harness/im Test
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # macht `import lib` in den Test-Modulen auffindbar

import lib  # noqa: E402


@dataclass
class Result:
    test: str
    variant: str
    outcome: str
    detail: str


def discover_tests(test_filter: str | None = None) -> list[type[lib.AttackTest]]:
    """Lädt die Module in tests/ und sammelt die AttackTest-Unterklassen."""
    classes: list[type[lib.AttackTest]] = []
    for path in sorted((HERE / "tests").glob("*.py")):
        if path.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(path.stem, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, lib.AttackTest) and obj is not lib.AttackTest and obj.META:
                if test_filter and test_filter not in (obj.META.get("id"), obj.__name__):
                    continue
                classes.append(obj)
    return classes


def run_one(test: lib.AttackTest, *, keep: bool) -> tuple[str, str]:
    """Führt einen Test aus und liefert (outcome, detail). Cleanup läuft immer,
    außer bei --keep."""
    try:
        try:
            test.attack()
        except lib.AttackBlocked as exc:
            return "blocked", str(exc)
        reachable = test.probe()
        return ("vulnerable" if reachable else "blocked"), test.detail
    except Exception as exc:  # noqa: BLE001 - Harness soll nicht abbrechen
        traceback.print_exc()
        return "error", f"{type(exc).__name__}: {exc}"
    finally:
        if keep:
            print("    (--keep: Cleanup übersprungen)")
        else:
            try:
                test.cleanup()
            except Exception as exc:  # noqa: BLE001
                print(f"    ! Cleanup fehlgeschlagen: {exc}", file=sys.stderr)
            test._rmtmp()


def print_table(results: list[Result]) -> None:
    headers = ("Test", "Variante", "Outcome", "Detail")
    cells = [(r.test, r.variant, r.outcome, r.detail) for r in results]
    widths = [len(h) for h in headers]
    for row in cells:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(str(value)))
    widths[3] = min(widths[3], 70)  # Detailspalte nicht künstlich aufblähen

    def fmt(row):
        return "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row))

    print("\n" + fmt(headers))
    print("-" * (sum(widths) + 2 * (len(headers) - 1)))
    for row in cells:
        print(fmt(row))
    print()


def write_markdown(results: list[Result], path: Path) -> None:
    lines = [
        "# Ergebnisse adversariale Tests",
        "",
        "| Test | Variante | Outcome | Detail |",
        "|---|---|---|---|",
    ]
    for r in results:
        detail = r.detail.replace("|", "\\|")
        lines.append(f"| {r.test} | {r.variant} | {r.outcome} | {detail} |")
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Adversariale Tests ausführen")
    parser.add_argument("--variant", choices=["baseline", "hardened", "all"], default="all")
    parser.add_argument("--test", default=None, help="nur diesen Test (META id oder Klassenname)")
    parser.add_argument("--keep", action="store_true", help="Cleanup auslassen (Debug)")
    args = parser.parse_args()

    variants = ["baseline", "hardened"] if args.variant == "all" else [args.variant]
    tests = discover_tests(args.test)
    if not tests:
        print("Keine Tests gefunden.", file=sys.stderr)
        return 1

    results: list[Result] = []
    for variant in variants:
        cfg = lib.VARIANTS[variant]
        reachable, reason = lib.variant_reachable(cfg)
        if not reachable:
            print(f"\n== Variante '{variant}': übersprungen ({reason}) ==")
            results += [Result(cls.META["id"], variant, "skipped", reason) for cls in tests]
            continue

        print(f"\n== Variante '{variant}' ==")
        for cls in tests:
            print(f"\n[{variant}] {cls.META['id']} — {cls.META.get('title', '')}")
            outcome, detail = run_one(cls(variant, cfg), keep=args.keep)
            print(f"    = {outcome}: {detail}")
            results.append(Result(cls.META["id"], variant, outcome, detail))

    print_table(results)
    results_path = HERE / "results.md"
    write_markdown(results, results_path)
    print(f"Ergebnistabelle geschrieben: {results_path}")

    # Exit != 0 nur bei Harness-/Testfehler, nicht bei einem gültigen Outcome.
    return 1 if any(r.outcome == "error" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
