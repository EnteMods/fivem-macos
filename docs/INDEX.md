# Documentation index

This index is the entry point for the Apple Silicon client source snapshot. The [repository README](../README.md) carries current app, join, update, and server status. Dated test records retain their original scope; the V4 and V5 joins on one installation are not a fresh-install or general compatibility result.

## Status and evidence

- [8 November update](UPDATES-2026-11-08.md): V4/V5 joins, server validation, staged client update, and remaining boundaries.
- [Known issues](KNOWN_ISSUES.md): corrected microphone-permission cause, remaining client and server limits, and open authentication and rendering work.
- [Tested LAN session](TESTED_LAN_SESSION.md): scope and limits of the 6 November 2026 source-LAN join and gameplay evidence.
- [Server overview](../server/README.md): the verified joins and their limits.

## Source and build

- [Architecture](ARCHITECTURE.md): native ARM64 and Windows-source tracks, runtime boundaries, and project structure.
- [Building](BUILDING.md): toolchain requirements and why this snapshot is not a fresh-install recipe.
- [Updates and reproducibility](UPDATES.md): source pins, candidate isolation, integrity checks, and rollback requirements.

## Licensing and notices

- [Project license](../LICENSE) and [license texts](../LICENSES/).
- [Third-party notices](../THIRD_PARTY_NOTICES.md). These files preserve component-specific terms; they do not by themselves establish that every possible redistribution is cleared.
