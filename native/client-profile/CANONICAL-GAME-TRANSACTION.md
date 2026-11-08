# Canonical GTA binding transaction

The schema-2 profile can select exactly one sibling install:

`GTA-V-macOS/prefixes/rockstar-legacy/drive_c/Program Files/Rockstar Games/Grand Theft Auto V Legacy`

Its reference is an object with exactly `kind: sibling-install` and that fixed `path`. It is relative to the parent of the FiveM project. It cannot supply an arbitrary absolute path or a `..` escape. Schema 1 retains its exact historical internal-clone path. The general relative-path validator remains unchanged. Every component below the trusted project parent is checked with `lstat`; game executable reads use the existing no-follow/single-file SHA-256 checks. Both schemas retain the same three executable inventory hashes, 422 stage hashes and 145 Rockstar code entries.

`run_current.check_binding` runs the full doctor first, then sets the frozen helper's `game.GAME` to the selected directory before the helper's inventory check. Frozen helper bytes, historical status/receipts, archived schema-1 profile, accounts, registry, stage, prefix identities, renderer and app signature are not rewritten by this migration.

The transaction affects exactly four active objects: active profile bytes, current binding bytes, the two content pins in `run_current.py`, and the existing prefix's `dosdevices/g:` symlink. Each file/link replacement is atomic. A filesystem cannot atomically replace these four objects together; the existing exclusive prefix lock prevents a cooperating launcher from starting during replacement, and any read-only preflight observing an intermediate combination fails closed. The plan retains small old/new snapshots. A caught failure after the first replacement restores all old snapshots. For an interrupted process or power loss, use the explicit rollback command below before attempting another launch. Rollback refuses files or a G: link with contents outside the exact old/new states.

No game data is copied or deleted. `CitizenFX.ini` remains `IVPath=G:`. No client is started by any command below.

## Prepare and review

Close all Wine/client/Rockstar processes first. The native FiveM launcher shell can remain open; the process guard recognizes only its exact app executable suffix as a shell. Prepare takes the prefix lock, runs the current complete preflight, checks all entries' metadata against the completed 443-file / 128918230441-byte full SHA comparison for both trees, and verifies the original three executables again. It creates one exclusive plan file and refuses overwrite:

```sh
python3 -B native/client-profile/canonical_game_transaction.py prepare
```

Review `research/single-install-consolidation-20261108/canonical-game-transaction/plan.json`. Its `files` contain base64-encoded full old/new small documents, plus each SHA-256. Decode them for review. The new binding records the previous profile and binding hashes, the full-comparison report hash, and the real new profile hash. The new launcher changes only its `PROFILE_SHA` and `BINDING_SHA` constants. Keep the reported `plan_sha256` for the next commands. An existing plan must be reviewed or explicitly retired before another prepare; this tool has no overwrite mode.

## Apply and rollback

After review, apply using the exact reported plan hash:

```sh
python3 -B native/client-profile/canonical_game_transaction.py apply --plan-sha256 <reviewed-plan-sha256>
```

Apply rechecks the current complete preflight, all old document hashes, prefix identity, raw G: text, report hash and both full metadata inventories under the prefix lock. It then atomically replaces the link and documents, runs the full doctor and a fresh `run_current.py --check`, and reports `APPLIED` only after both pass. It retains the internal GTA clone for an actual client/server acceptance test. Runtime acceptance and later clone deletion remain separate, explicitly scoped work.

If the transaction fails or the subsequent actual test warrants reverting while the old clone still exists:

```sh
python3 -B native/client-profile/canonical_game_transaction.py rollback --plan-sha256 <reviewed-plan-sha256>
```

Rollback accepts an old, new or interrupted mixture of the exact planned bytes. Before changing any active object, it rechecks the complete pinned comparison and both game trees; a removed or changed clone therefore stops rollback without changing the working schema-2 binding. It then restores all four old values and runs a fresh old launcher preflight. A third-party modification, prefix replacement, missing/changed old game, or running client requires investigation rather than overwriting it. Neither direction changes the contents or pins of helper snapshots.

## Verification

```sh
python3 -B -m unittest discover -s native/client-profile -p 'test_*.py'
python3 -B native/client-profile/doctor.py
python3 -B native/client-profile/run_current.py --check
```

The isolated fixtures cover both schemas, path/reference rejection, parent/executable symlinks, hard links, changed executable bytes, stale G: mapping, unchanged old-schema support, validated helper-path assignment before candidate verification, pin derivation from real bytes, interrupted-state restoration, unrelated-change rejection, and rollback after failed postapply validation. These checks do not establish a successful client/server session.

## Existing-installation acceptance (8 November 2026)

The original-game binding passed a real restricted V5 join through visible world entry and normal quit. Open-file metadata identified 179 original-installation files, including 176 RPF archives, and zero clone files. A separately scoped cleanup subsequently removed the redundant 553-entry game clone under the prefix lock after the pinned inventories and open-handle checks passed. The final 422/145/3 preflight passed.

The old clone rollback is no longer available; the CLI refuses it before rewriting active files. Historical direct helper/schema-1 paths remain historical. The 37 fixture tests include refusal before any active-object change when clone validation fails. This is existing-installation acceptance, not a portable bootstrap or normal ticket-authenticated admission.
