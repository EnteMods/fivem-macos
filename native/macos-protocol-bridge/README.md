# Local Cfx browser-return bridge

This ARM64 AppKit application forwards the normal `fivem://accept-auth` browser return to the already running, locally bound Wine client. It preserves the opaque URL, sends it to the helper on stdin and suppresses child stdout/stderr. It does not create a Cfx multiplayer ticket, impersonate a platform or change authentication/security decisions.

The owner confirmed a real Cfx account-linking return with version 0.1.1 on 6 November 2026. That helper replaced an obsolete prelogin mount-identity check with the same complete current binding verification used by the launcher. Lock, session, controller, executable inventory and current prefix checks remain required. Account linking is separate from the unresolved `cfxTicket2` provider.

Version 0.1.2 closes only the bridge app when the secondary process exits normally with code 0. A 30-second wait timeout now reports pending (code 6), leaves the bridge open and does not terminate the client. Other failures stay visible. This process outcome is the available handoff confirmation; it is not an independent verification of the account state inside FiveM.

## Local build and checks

```sh
mkdir -p build
python3 -B -m unittest discover -s native/macos-protocol-bridge -p test_handoff.py
python3 -B native/macos-protocol-bridge/build.py
```

The builder compiles the route/status fixtures and ARM64 app, creates an isolated helper snapshot, pins its hash in the app and verifies a local ad-hoc signature. It does not register the app, use a real URL, launch FiveM or alter macOS security settings. The 0.1.2 build passed 14 Python tests and Swift fixtures for 31 routes and 9 completion states. The new auto-close behavior has not been exercised through another real OAuth session.

Keep the entire generated build directory: the app references the hash-pinned helper beside its bundle. The helper still depends on the project's current installation-specific runner, profile and historical build inputs. This is source evidence for an existing setup, not a portable installer or a fresh-install account-linking guarantee. `handoff.py` is the preserved older helper; current builds use `handoff_current.py`.

Never put real browser-return URLs, credentials, ticket values, account data or private build reports into issues. These sources and synthetic tests contain no real callback payload.
