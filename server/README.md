# Isolated FiveM LAN development test

This describes the project's **test setup**, not a server fork or a ready-to-deploy production service. The recorded instance used the unchanged official FiveM Linux Recommended artifact 38317 and `sv_lan true` for the entire instance. No operating-system-specific ticket exception was implemented, and the server's ticket or security code was not changed. A client-reported operating system is not trusted platform attestation. Normal client-side GTA/Rockstar authentication remains necessary.

## Recorded scope and limitations

On 6 November 2026, TCP `/info.json` and UDP `getinfo` health checks succeeded from the intended test client. Separate bridge-container checks were blocked and all four dedicated firewall rule counters increased. An independent unauthorized external source was not available for testing. These observations concern that particular configuration at that time; they do not establish ongoing availability or a general firewall guarantee.

**A FiveM join was attempted and failed during resource initialization.** The client reached handshake and the start of resource loading, then reported a missing mounter for `mapmanager`; its log classified the resource URI scheme as `ci`. No spawn or gameplay was demonstrated. Normal public-server admission and Cfx ticket issuance were not proven. The macOS client still has the limitations described in [known issues](../docs/KNOWN_ISSUES.md).

LAN mode alone was insufficient with this standard binary distribution. [Cfx issue #3654](https://github.com/citizenfx/fivem/issues/3654) describes a public source-built server as an alternative for development clients. The project is preparing that separate build at the matching source revision using the upstream public CI route. The existing server remains in place until an artifact is built and checked; a built or deployed replacement is not claimed yet. No client URI rewrite or fabricated ci implementation is used. Track [issue #8](https://github.com/EnteMods/fivem-macos/issues/8).

## Components and operating model

The recorded server used the official artifact [38317](https://runtime.fivem.net/artifacts/fivem/build_proot_linux/master/38317-88a413835e9d7f56633f249880a13f42297153a2/fx.tar.xz), SHA-256 `9442f8211b927a4bdefa0bc144a63d05dc44c0260726737a986529b3a88468c8`, and a separate checkout of [cfx-server-data](https://github.com/citizenfx/cfx-server-data) at `c6afa3909c763e3327ed76825e78453286c99f05`. The archive, resources, game files and credentials are not included. Obtain and verify upstream material separately and follow its applicable terms; see the repository's [third-party notices](../THIRD_PARTY_NOTICES.md).

The private test used a dedicated Docker bridge and TCP/UDP game ports restricted to an allowed source, with a host firewall guard checked before server startup. It did not publish a txAdmin port. The server configuration and owned license key remained private on the host. The container used open standard input and no Docker restart policy; systemd coordinated startup with the guard.

The original firewall and service files are specific to that host, addressing and Docker topology. They are intentionally not included as a generic security recipe: a firewall rule, service ordering or startup check alone does not prove isolation for a different host, IPv6 configuration, port binding or packet path. Before running a test, the operator must design and independently verify restrictions for their own environment, including access from outside the host. Store the server key outside the repository with restrictive permissions. Never publish keys, account data, logs containing private information, or game/client files.

## Read-only local check

On the Docker host, `./server/inspect-container.sh <container-name>` prints selected state for an existing container. It does not start or stop anything, test network isolation or inspect the server configuration. The name is supplied by the operator; do not post the output without checking it for local context. A running container does not establish server health or successful gameplay.

For actual validation, separately check the intended TCP and UDP health endpoints, test denied access using an independent source, and exercise a real authorized client join, spawn and gameplay. Record exact environment and results without credentials or ticket values. Review [issue #6](https://github.com/EnteMods/fivem-macos/issues/6) for the outstanding acceptance work.

## Authentication development boundary

Contributions should investigate documented, authorized provider interfaces and reproducible Wine/API compatibility behavior. Do not fabricate tickets, weaken checks, or infer identity or trust from a client-provided OS. No OS-selective admission mechanism or production security property is claimed here.
