# Known issues

## Tracked work

- [#1 — Missing cfxTicket2 / authentication provider](https://github.com/EnteMods/fivem-macos/issues/1)
- [#2 — Unchanged adhesive.dll load failure on Wine](https://github.com/EnteMods/fivem-macos/issues/2)
- [#3 — Portable fresh-install bootstrap](https://github.com/EnteMods/fivem-macos/issues/3)
- [#4 — Reversible updates and regression gates](https://github.com/EnteMods/fivem-macos/issues/4)
- [#5 — Retina, fullscreen and mouse-coordinate QA](https://github.com/EnteMods/fivem-macos/issues/5)
- [#6 — Complete isolated LAN multiplayer acceptance](https://github.com/EnteMods/fivem-macos/issues/6)
- [#7 — Rockstar connection error 506 before the menu](https://github.com/EnteMods/fivem-macos/issues/7)
- [#8 — Resource URI has no matching ci mounter](https://github.com/EnteMods/fivem-macos/issues/8)

## Isolated LAN join: observed mounter failure resolved

The controlled 6 November join attempt reached server variables, handshake and resource loading, then failed on `mapmanager`. The fixed-field log reader classified the missing resource URI scheme as `ci`; it exports no URI payload. The public cache mounter handles `global`, while ResourceNetBindings accepts a server-supplied URI override. The deployed mapmanager source matched its pinned public checkout and uses a recognized manifest version. This does not establish the private ci-provider contract or correct package contents.

The unchanged official Recommended server with instance-wide LAN mode was therefore insufficient for this source/Wine test. [Cfx issue #3654](https://github.com/citizenfx/fivem/issues/3654) describes using a public source-built server as a development alternative. The matching public server build was subsequently compiled, checked without network access and deployed only to the owner's restricted test instance. The existing Mac client completed resource loading and game initialization; the owner confirmed movement, camera and general interaction. No ci adapter or URI rewrite was applied. See the [tested session](TESTED_LAN_SESSION.md) and [issue #8](https://github.com/EnteMods/fivem-macos/issues/8). This resolves the observed mounter error for this combination, not public-server authentication.

## Source-server shutdown

An earlier source-server version exited 139 after SIGINT. The deployed V5 combines the pinned 88a source, V4 shutdown changes and selected upstream changes from `789269293f241bca2098adb96db4a5a7319105d4` across seven files. It passed 15 CitiTest cases with 2,812,163 assertions and five natural SIGINT/console shutdowns. A real client subsequently joined and quit normally, leaving the server healthy. This evidence applies to that deployment; a clean public bootstrap remains open.

## Intermittent Rockstar 506 and observed recovery

After a successful local integrity preflight on 6 November, a controlled launch displayed Rockstar connection error 506 and stopped before the menu or a server join. There was no automatic login timeout. The private Cfx log confirms this error, but the accompanying Rockstar log entries are from the preceding day. An expired session, launcher/service startup condition or SDK connectivity is a hypothesis, not an established cause.

In a subsequent retry, the owner completed normal authentication in the unchanged standalone Rockstar Launcher in the same prefix. Its live session was handed over without terminating it, and FiveM reached a visibly rendered menu. Fresh Rockstar logs also recorded service connection, handshake, PreInit and UI startup. This is one observed recovery; repeatability and persistent session reuse remain unverified. Authentication and licensing were not modified. See [issue #7](https://github.com/EnteMods/fivem-macos/issues/7).

## Native microphone permission and observed join

On 8 November, native diagnostics attributed the resource-download hang to a persistent TCC abort inside Wine: `local.fivem-macos.launcher` lacked `NSMicrophoneUsageDescription`. The 0.1.1 build/app metadata correction and the owner granting standard macOS Documents and microphone permissions cleared the observed hang for unchanged client 1257409 on the live V4 server and subsequently on the deployed V5 server. The verified sequence completed resource download, protocol acknowledgement, network game initialization, and final game load; the owner confirmed joining. These joins establish behavior on one installation, not full voice, performance, or fresh-install acceptance. No TCC database change or authentication exception was made.

## Cfx account-linking bridge

A normal Cfx browser return was confirmed by the owner with bridge 0.1.1 on 6 November. Its helper now uses the complete current launcher binding instead of comparing against an archived prelogin mount identity. Version 0.1.2 adds bridge-only closing after a normal secondary-process exit; pending or failed handoffs keep the window open. Fourteen Python tests and Swift route/status fixtures passed. The new close behavior has not been exercised through another real OAuth session. This is still an installation-specific helper, not a portable setup. See [bridge sources and limits](../native/macos-protocol-bridge/README.md). Account linking does not by itself establish a genuine multiplayer ticket.

## Multiplayer authentication

Two earlier measured Wine connection attempts reached the authentication interception point with no handler at the observed instance and time. The ordinary request continued without `cfxTicket2`, and the server rejected the missing field. This establishes an observed boundary, not the identity or location of a ticket provider. Steam linking, Rockstar ownership and Cfx account linking are distinct states; none is shown to replace the missing provider.

The upstream Wine path selects its original insecure-mode component and displays its warning. This project does not treat bypassing or changing security checks as a compatibility solution.

## Adhesive loader observation

In isolated diagnostic contexts, an unchanged official component failed during executable loading with Windows error 998. A bounded observer recorded a read fault at component RVA `0xD8E9B4`. In one Wine build, the observed export-name count was 1463 and a candidate index was 1496; in an independent Wine 11.21 runtime and fresh prefix, the corresponding values were 1481 and 1489. The second environment changes both runtime and prefix, so it is not a single-variable comparison.

For the first environment, a bounded 43,656-byte export span matched between the loaded Wine system image and a private read/write copy after validating the expected mapping-base difference. The names were also checked as correctly sorted. The sought export may be a function or a data object; it is unknown. A missing export, private provider condition or host/runtime difference remains a hypothesis, not a demonstrated cause. No export is fabricated and no success is forced.

## Installation, updates and display

- The schema 2 original-GTA binding passed a real V5 join and normal quit on the existing installation. Open-file evidence identified 179 original-installation files, including 176 RPF archives, and none from the redundant clone. The clone was removed after the complete stored metadata inventories were rechecked under the prefix lock; the final 422/145/3 preflight passed. This does not establish a portable installer.
- Client content 1257529 and three associated upstream DLLs are staged only; their runtime behavior is unverified.
- A portable fresh-install workflow and per-install binding/receipt bootstrap do not yet exist. Existing profile and launcher helpers are tied to a prior local setup.
- Source-client update, rollback and regression gates need a reproducible end-to-end workflow. Official production files must stay separate from source candidates.
- Retina resize, fullscreen transitions and mouse coordinate behavior require consistent device-level QA. Earlier partial observations are not a complete current fix.
- Isolated V4 and V5 source-LAN joins were demonstrated on one installation; basic game interaction was confirmed in the earlier session. Repeatable disconnect/reconnect, long-duration play, multiple clients, broader resources and performance remain unverified. No independent external blocked-source test was available. The server is an instance-wide LAN development configuration, not an OS-selective authentication fork.
