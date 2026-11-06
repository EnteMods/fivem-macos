# FiveM on Apple Silicon: source-port work

This repository contains source work and diagnostic tools for running a FiveM client on Apple Silicon. It is an experimental port, not a packaged client or a promise of multiplayer compatibility. You need your own legitimately obtained game and client files. This source release contains no game assets, official client binaries, runtime bundles, account profiles, tickets, or SDK binaries.

## AI-assisted development and help wanted

This project was developed with substantial help from AI coding agents, directed by the project owner. Review the code, test coverage and stated limits rather than assuming that generated changes are correct.

**A legitimate solution for the missing `cfxTicket2` is still being sought. Help is welcome.** Useful contributions include reproducible ordinary Wine/API compatibility findings, documented authorized provider interfaces, build portability fixes and independent testing. Please keep observations separate from hypotheses and never post credentials, ticket values, proprietary DLL payloads or game files in issues.

This project is not supported or endorsed by Cfx.re, Rockstar Games or Take-Two.

## Current status

The project owner has previously reported a usable local interface and single-player experience. On 6 November 2026, the recorded work was a preflight of 422 client files, 145 approved vendor program files and three game executables, together with two test groups of 9 and 14 checks. No client start, end-to-end session or server join was performed in that verification. Historical observations are not a fresh-install guarantee.

A subsequent controlled client start on the same day stopped before the menu with Rockstar Launcher connection error **506**. After the owner completed a normal login in the unchanged standalone Rockstar Launcher in the same prefix, a retry reached the FiveM menu. The live Rockstar session was handed over without a timeout or forced termination. This single successful recovery does not establish a persistent fix; [issue #7](https://github.com/EnteMods/fivem-macos/issues/7) remains open for startup reliability. The publication checks also passed 63 selected tests; this is not a full client or fresh-install acceptance run.

The public upstream Windows-source reference is commit `88a413835e9d7f56633f249880a13f42297153a2`. The older native ARM64 patch queue has its own base and file pins in [config/native-port.json](config/native-port.json); do not assume both source bases are interchangeable. The separately installed official production client, content version `1257409`, remained unchanged during the recorded source-port work.

Multiplayer is unresolved. Earlier measured attempts reached the client authentication interception point without a handler at the observed instance and time; the server rejected the request for a missing Cfx connection ticket. The public source does not establish a supported independent ticket issuer. The normal Wine component selection and its insecure-mode warning remain in effect. See [known issues](docs/KNOWN_ISSUES.md).

### Server compatibility

Do not expect this client to join normal ticket-authenticated FiveM servers. Current testing is limited to the project's own isolated compatibility test environment. The server runs the official Recommended Linux build `38317` in LAN development mode, with scoped network restrictions. TCP/UDP health checks and a blocked-source container check passed; an independent external blocked-source test was not available. A client join reached handshake and resource loading, then failed because no mounter handled a `ci` resource URI. A matching public source-built server is being prepared as the upstream-described development alternative; no completed replacement, spawn or gameplay is claimed. See [issue #8](https://github.com/EnteMods/fivem-macos/issues/8). An OS-selective authentication-exemption fork is not implemented. A client-reported OS is not trusted platform attestation.

This restriction is a testing boundary, not a claim that a working custom server or a valid Cfx ticket already exists. No public server is a test target without authorization.

## Start here

- [Architecture and boundaries](docs/ARCHITECTURE.md)
- [Build prerequisites and current limitations](docs/BUILDING.md)
- [Source and official-client updates](docs/UPDATES.md)
- [Open issues](docs/KNOWN_ISSUES.md)
- [Isolated LAN test scope and read-only server inspection](server/README.md)

The checked-in `native/client-profile/run_current.py` is tied to an existing local binding and helper artifacts. It is included as source evidence, not as a portable fresh-install launcher. A safe per-install bootstrap is still missing. There is no ready-to-use DMG or supported one-command installation in this repository.

This release is source-available: sale of the project's original contributions is restricted under its current license. Read the exact license and upstream notices accompanying the release; upstream material has its own terms. Earlier versions granted under MIT remain subject to the permissions granted for those versions; upstream material retains its own terms.
