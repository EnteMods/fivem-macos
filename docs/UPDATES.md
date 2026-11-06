# Updates and reproducibility

Treat the official production client and the source-port candidate as separate installations. The recorded production client was content version `1257409`; this observation does not guarantee any later version or deployment. The Windows-source reference used for the current work is `88a413835e9d7f56633f249880a13f42297153a2`. The native ARM64 patch queue uses the separate base recorded in [config/native-port.json](../config/native-port.json).

Before accepting a source or client update, record the exact version and file identities, audit relevant public source and dependency changes, build in an isolated location, and verify the candidate against its own reviewed manifest. Preserve the original installation and retain a tested rollback path. Re-run relevant launch, display and authentication-boundary checks only in an authorized test environment. A passing compile or hash check does not establish gameplay or an accepted server connection.

The scripts under [scripts](../scripts/) document existing guarded work, but a portable update transaction with fresh-install receipts, rollback and regression gates is not complete. Existing local profile hashes and generated artifacts are not universal release pins. Do not copy another installation's credentials or profile to satisfy those checks.
