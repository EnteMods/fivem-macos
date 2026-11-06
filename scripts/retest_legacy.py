#!/usr/bin/env python3
"""Retired entry point: never launch the copied account-bearing client prefixes."""

import sys


def main():
    print(
        "Legacy-Client-Retest deaktiviert: Die alten Präfixe fivem-legacy und "
        "fivem-enhanced-probe wurden aus der GTA-Umgebung kopiert und können "
        "Rockstar-Kontodaten enthalten. Dieser Einstieg startet weder diese "
        "Präfixe noch einen offiziellen FiveM-Client.\n"
        "Aktuelle Diagnose ohne Konten: python3 scripts/corert_regression.py all\n"
        "Microsoft-C++-Toolchain prüfen: python3 toolchains/smoke/run-smoke.py\n"
        "Diese eigenen Probes verwenden ausschließlich den markierten "
        "Präfix prefixes/corert-regression. Für einen späteren Client-Test "
        "ist eine eigene ausdrückliche Freigabe erforderlich.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
