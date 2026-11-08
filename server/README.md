# Isolated source-LAN server test

## Current client state

On 8 November 2026, the 0.1.1 microphone metadata correction and owner-granted
macOS Documents/microphone permissions cleared the observed resource hang for
unchanged Windows client 1257409 first on the live V4 server and then on the deployed V5 server. Resource download,
protocol acknowledgement, network game initialization, and final game load
completed; the owner confirmed joining. The signature, selftest, and earlier 422-file profile
checks passed. The V5 session ended with a normal quit and the server remained healthy. These joins cover one installation, not full voice, performance, or
fresh-install acceptance. No TCC database change or authentication exception
was made. See the [current status](../README.md).

The V5 server uses pinned 88a source, V4 shutdown changes and seven files of selected upstream changes from `789269293f241bca2098adb96db4a5a7319105d4`. It passed 15 CitiTest cases (2,812,163 assertions) and five natural SIGINT/console shutdowns.

## Earlier LAN evidence

On 6 November, an existing Apple Silicon installation joined a matching
public-source Linux FXServer. The owner confirmed movement, camera control,
and interaction. Read the [dated session record](../docs/TESTED_LAN_SESSION.md)
for that test combination and its limits.

That server used upstream's instance-wide `sv_lan true` mode. It was not an
OS-selective ticket exception. The client did not rewrite resource URIs or
imitate a private provider. Normal Cfx ticket issuance and public-server
admission remain unresolved.

This client repository includes no ready server bundle, operator
configuration, credentials, game content, or general network-isolation
recipe. See [known issues](../docs/KNOWN_ISSUES.md) and the
[documentation index](../docs/INDEX.md).
