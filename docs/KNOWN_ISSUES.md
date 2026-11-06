# Known issues

## Tracked work

- [#1 — Missing cfxTicket2 / authentication provider](https://github.com/EnteMods/fivem-macos/issues/1)
- [#2 — Unchanged adhesive.dll load failure on Wine](https://github.com/EnteMods/fivem-macos/issues/2)
- [#3 — Portable fresh-install bootstrap](https://github.com/EnteMods/fivem-macos/issues/3)
- [#4 — Reversible updates and regression gates](https://github.com/EnteMods/fivem-macos/issues/4)
- [#5 — Retina, fullscreen and mouse-coordinate QA](https://github.com/EnteMods/fivem-macos/issues/5)
- [#6 — Complete isolated LAN multiplayer acceptance](https://github.com/EnteMods/fivem-macos/issues/6)
- [#7 — Rockstar connection error 506 before the menu](https://github.com/EnteMods/fivem-macos/issues/7)

## Current launch blocker: Rockstar 506

After a successful local integrity preflight on 6 November, a controlled launch displayed Rockstar connection error 506 and stopped before the menu or a server join. There was no automatic login timeout. The private Cfx log confirms this error, but the accompanying Rockstar log entries are from the preceding day. An expired session, launcher/service startup condition or SDK connectivity is a hypothesis, not an established cause. The next check is a normal standalone Rockstar launch in the same prefix, followed by a controlled FiveM retry. Authentication and licensing must complete through the original supported paths.

## Multiplayer authentication

Two earlier measured Wine connection attempts reached the authentication interception point with no handler at the observed instance and time. The ordinary request continued without `cfxTicket2`, and the server rejected the missing field. This establishes an observed boundary, not the identity or location of a ticket provider. Steam linking, Rockstar ownership and Cfx account linking are distinct states; none is shown to replace the missing provider.

The upstream Wine path selects its original insecure-mode component and displays its warning. This project does not treat bypassing or changing security checks as a compatibility solution.

## Adhesive loader observation

In isolated diagnostic contexts, an unchanged official component failed during executable loading with Windows error 998. A bounded observer recorded a read fault at component RVA `0xD8E9B4`. In one Wine build, the observed export-name count was 1463 and a candidate index was 1496; in an independent Wine 11.21 runtime and fresh prefix, the corresponding values were 1481 and 1489. The second environment changes both runtime and prefix, so it is not a single-variable comparison.

For the first environment, a bounded 43,656-byte export span matched between the loaded Wine system image and a private read/write copy after validating the expected mapping-base difference. The names were also checked as correctly sorted. The sought export may be a function or a data object; it is unknown. A missing export, private provider condition or host/runtime difference remains a hypothesis, not a demonstrated cause. No export is fabricated and no success is forced.

## Installation, updates and display

- A portable fresh-install workflow and per-install binding/receipt bootstrap do not yet exist. Existing profile and launcher helpers are tied to a prior local setup.
- Source-client update, rollback and regression gates need a reproducible end-to-end workflow. Official production files must stay separate from source candidates.
- Retina resize, fullscreen transitions and mouse coordinate behavior require consistent device-level QA. Earlier partial observations are not a complete current fix.
- A complete LAN multiplayer session and gameplay have not been demonstrated. The isolated official Recommended 38317 LAN server is running with scoped network restrictions; TCP/UDP health checks and blocked-container checks passed. No successful FiveM client join or gameplay result is available, and no independent external blocked-source test was available. The server is an instance-wide LAN development configuration, not an OS-selective authentication fork.
