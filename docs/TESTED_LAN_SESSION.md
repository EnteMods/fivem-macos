# Tested source-LAN session — 6 November 2026

The existing Apple Silicon Mac installation joined the owner's isolated public-source FXServer and loaded the game. The owner confirmed character movement, camera control and general interaction, then ended the session and changed graphics settings for further testing. No performance result was measured.

## Tested combination

- Public Windows-client source reference: `88a413835e9d7f56633f249880a13f42297153a2` with the project's existing reviewed compatibility components, Wine and DXMT runtime.
- GTA V Legacy game build: `3889`; a legitimately installed, separately supplied game.
- Public Linux x86-64 server source: the same `88a4138` revision, built through upstream's public Alpine CI script. The exact built `FXServer` SHA-256 is `0a663b42514d48aba91571e2990f6903b0b7949dac22bf0b1f5f5cc3cdd3b855`.
- Public server-data revision: `c6afa3909c763e3327ed76825e78453286c99f05`, with public `mapmanager`, `spawnmanager`, `basic-gamemode`, `fivem-map-hipster` and separately built public `chat` resources.
- Instance-wide upstream LAN development mode, maximum four clients, dedicated Docker network, scoped IPv4 game ports, no public administration port. The network guard was checked before and after replacement. This is not a general deployment security guarantee; an independent unauthorized external-source test remains missing.

## Evidence and resource error

The earlier unchanged Recommended `38317` binary server, even in LAN mode, supplied a resource URI whose `ci` scheme had no mounter in the source client. The error was `Could not get resource mounter for resource mapmanager.`

After switching only the isolated server to the matching public-source build, the existing client recorded, in order:

1. Server variables and handshake.
2. Resource download started and completed.
3. Server protocol acknowledgement.
4. Network-connected initial game load.
5. Game load finalized.

There was no mounter failure in this attempt. The server reported one player, a native window capture showed the game, and the owner confirmed actual interaction. Private raw logs, screenshots, account names, addresses and identifiers are retained locally rather than distributed here. The fixed-field log reader reports phases without exporting URI payloads or ticket values.

The separate public-development package omits only the unbuilt `svadhesive` metadata entry, following the condition in upstream `code/tools/ci/wsl-build.sh` at this revision. Original metadata is retained. The public authentication and ticket code was not patched, and no private security component, fabricated ticket or client OS attestation was substituted.

## Remaining limits

- This establishes the tested source-LAN combination only. Normal Cfx ticket issuance, public-server admission and regular anti-cheat compatibility remain unresolved.
- No OS-selective ticket exception exists. LAN mode applies to the entire development instance.
- A repeatable disconnect/reconnect sequence, long-duration play, multiple players, third-party resources, higher graphics settings and performance remain separate tests.
- The source-server smoke logs `Quitting` after SIGINT but exits with code 139, without OOM. One isolated reproduction localized a fault to a Node tick during shutdown; full backtrace and a verified fix are still missing. Do not treat the shutdown as clean.
- Source compilation, this local session and selected automated checks do not establish a portable installer. The current local profile is installation-specific; no ready DMG or complete fresh-install workflow is claimed.
