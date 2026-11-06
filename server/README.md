# Isolated FiveM LAN development test

This describes the project's **tested development setup**, not a ready-to-deploy production service. The current isolated instance uses the matching public-source Linux FXServer at `88a413835e9d7f56633f249880a13f42297153a2` and `sv_lan true` for the entire instance. No operating-system-specific ticket exception was implemented, and the public server's ticket or authentication code was not changed. A client-reported operating system is not trusted platform attestation. Normal client-side GTA/Rockstar authentication remains necessary.

## Recorded scope and limitations

On 6 November 2026, TCP `/info.json` and UDP `getinfo` health checks succeeded from the intended test client. Separate bridge-container checks were blocked and all four dedicated firewall rule counters increased. An independent unauthorized external source was not available for testing. These observations concern that particular configuration at that time; they do not establish ongoing availability or a general firewall guarantee.

An initial join to the unchanged official Recommended binary failed during resource initialization: its `ci` resource URI had no mounter in the source client. After replacing only the isolated server with the matching public-source build, **resource download, protocol acknowledgement and game initialization completed**, and the owner confirmed character movement, camera and general interaction. Read the [tested session](../docs/TESTED_LAN_SESSION.md) for exact boundaries. Normal public-server admission and Cfx ticket issuance were not proven.

LAN mode alone was insufficient with that standard binary distribution. [Cfx issue #3654](https://github.com/citizenfx/fivem/issues/3654) describes a public source-built server as an alternative for development clients. The replacement uses upstream's public Alpine CI route. Its public-development package omits only the unbuilt `svadhesive` metadata entry as upstream's `wsl-build.sh` does for this build; original metadata is retained. No client URI rewrite or fabricated ci implementation is used. Track [issue #8](https://github.com/EnteMods/fivem-macos/issues/8).

## Components and operating model

The source-built `FXServer` SHA-256 is `0a663b42514d48aba91571e2990f6903b0b7949dac22bf0b1f5f5cc3cdd3b855`, paired with [cfx-server-data](https://github.com/citizenfx/cfx-server-data) revision `c6afa3909c763e3327ed76825e78453286c99f05` and separately built public system resources. Source-build recipes and the distributable Linux bundle are being prepared separately; no runtime bundle, game files or credentials are included in this client repository. Follow the applicable upstream terms and [third-party notices](../THIRD_PARTY_NOTICES.md).

The private test uses a dedicated Docker bridge and TCP/UDP game ports restricted to an allowed source, with a host firewall guard checked before server startup. It publishes no txAdmin port. The source-LAN configuration is fresh and contains no operator key; no previous accounts or private caches were copied into it. The container uses open standard input and no Docker restart policy; systemd coordinates startup with the guard.

The isolated SIGINT stop test ended with code 139 after logging `Quitting`, without OOM. Shutdown is under investigation and must not be described as clean. See [known issues](../docs/KNOWN_ISSUES.md).

The original firewall and service files are specific to that host, addressing and Docker topology. They are intentionally not included as a generic security recipe: a firewall rule, service ordering or startup check alone does not prove isolation for a different host, IPv6 configuration, port binding or packet path. Before running a test, the operator must design and independently verify restrictions for their own environment, including access from outside the host. Store the server key outside the repository with restrictive permissions. Never publish keys, account data, logs containing private information, or game/client files.

## Read-only local check

On the Docker host, `./server/inspect-container.sh <container-name>` prints selected state for an existing container. It does not start or stop anything, test network isolation or inspect the server configuration. The name is supplied by the operator; do not post the output without checking it for local context. A running container does not establish server health or successful gameplay.

For actual validation, separately check the intended TCP and UDP health endpoints, test denied access using an independent source, and exercise a real authorized client join, spawn and gameplay. Record exact environment and results without credentials or ticket values. Review [issue #6](https://github.com/EnteMods/fivem-macos/issues/6) for the outstanding acceptance work.

## Authentication development boundary

Contributions should investigate documented, authorized provider interfaces and reproducible Wine/API compatibility behavior. Do not fabricate tickets, weaken checks, or infer identity or trust from a client-provided OS. No OS-selective admission mechanism or production security property is claimed here.
