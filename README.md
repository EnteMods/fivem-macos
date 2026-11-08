# FiveM for Apple Silicon: experimental source port

Experimental FiveM client source port for Apple Silicon. This repository is
not an installer or a compatibility promise. Bring your own legitimate game
and client files. No game assets, official binaries, runtime bundles, account
profiles, tickets, or SDK binaries are included.

## Current status

Status snapshot: 8 November 2026. Verified local runs are separated from staged updates and unfinished installation work.

| Area | Current evidence | Boundary |
| --- | --- | --- |
| Main app | Native ARM64 app 0.1.1 with AuthBridge 0.1.2. Spotlight, signature, selftest, and the earlier 422-file profile `--check` passed. The 0.1.1 microphone metadata fix plus owner-granted Documents/microphone permissions cleared the observed resource hang for unchanged Windows client 1257409 on V4, followed by a verified join to the updated V5 server. Download, protocol ACK, network game initialization, and final game load completed; the owner confirmed joining. | V4 and V5 joins on one installation; the revised original-GTA binding still needs a live control test. Full voice, performance, and fresh-install acceptance remain untested. No TCC database change or authentication exception was made. |
| Production client update | Version 1257529 is isolated and staged; all 419 files were checked, with 61 changes. All three public update DLLs compiled and named-consumer checks passed. Pinned Wine exports contain the names flagged by two pre-existing API-set checker results. | Not activated. External runtime behavior remains unproven. |
| Client and server source | Tested source-LAN history uses upstream commit `88a413835e9d7f56633f249880a13f42297153a2`. Upstream master `5c3065c` is ten commits ahead. Recommended server `38435` is a comparison reference. | The pinned source plus backports is not a full build of that newer master. |
| LAN session | An existing Windows client 1257409 joined the updated V5 source-LAN server after the microphone metadata and owner-granted macOS permissions were corrected. Resource download, protocol ACK, network game initialization, and final game load completed. | One installation; the V5 session ended normally and the server remained healthy. Voice chat, performance, a fresh install, normal public-server admission, and ticket authentication are not established. |
| Server shutdown | V5 passed 15 CitiTest cases (2,812,163 assertions), five natural shutdown cycles and a real Mac client join after deployment. | A selected upstream backport over the V4 source runtime; a clean public bootstrap and public binary distribution remain open. |

## Start here

The [documentation index](docs/INDEX.md) maps the detailed records.

- [Architecture](docs/ARCHITECTURE.md) separates the native ARM64 and Windows-source tracks.
- [Building](docs/BUILDING.md) lists toolchains and explains the fresh-install limits.
- [Updates](docs/UPDATES.md) describes source pins, candidate isolation, and rollback.
- [Known issues](docs/KNOWN_ISSUES.md) tracks open work and observed boundaries.
- [LAN session](docs/TESTED_LAN_SESSION.md) records the historical join and gameplay evidence.
- [November 8 update](docs/UPDATES-2026-11-08.md) records the app, server and ticket follow-up.
- [Server overview](server/README.md) explains the tested development setup.

## Installation boundary

The local client binding in `native/client-profile/run_current.py` depends on
installation-specific state and helper artifacts. It is source evidence, not a
portable launcher.

The schema 2 original-GTA binding passed a real V5 world-entry and normal-quit control test; the redundant internal game clone has been removed. A per-install bootstrap, fresh-install workflow, and supported one-command
install are unfinished. No ready DMG or client binary download is included.

## Compatibility limits

Normal Cfx ticket-authenticated multiplayer remains unresolved. The public
source does not identify a supported independent `cfxTicket2` issuer. No
ticket solution, authentication bypass, or regular anti-cheat compatibility
is claimed.

Wine keeps its ordinary component selection and insecure-mode warning. The
tested server uses upstream's instance-wide `sv_lan true` mode. It is not an
OS-selective exception; a client-reported OS is not platform attestation.

Do not use an unauthorized public server as a test target. The LAN join does
not establish public-server admission or repeatable long-duration play.

## Contributing and licensing

Contributions can document reproducible Wine/API findings, authorized
provider interfaces, build portability, or independent tests. Separate
observations from hypotheses. Do not post credentials, ticket values, game
files, or proprietary DLL payloads. Cfx.re, Rockstar Games, and Take-Two do
not support or endorse this project.

Sale of original project contributions is restricted by the included license.
Earlier MIT grants remain valid for the versions they covered. Upstream and
third-party material keeps its own terms.

Read [LICENSE](LICENSE), [license files](LICENSES/), and [third-party
notices](THIRD_PARTY_NOTICES.md) before redistribution.
