# Building and prerequisites

This is a source snapshot, not a verified fresh-install recipe. A new installation cannot currently reproduce the locally bound client launch from the published files alone. In particular, per-install profile and receipt generation, dependency acquisition, device-specific verification and recovery remain unfinished.

## Native ARM64 source track

[scripts/native_port.py](../scripts/native_port.py) contains the `audit`, `prepare`, `build` and `test` actions. [config/native-port.json](../config/native-port.json) defines the older patch-queue base revision, patch digests and expected source inputs. The audit requires the exact commit and required upstream objects to be present locally; preparation and builds require the applicable source tree, submodules, macOS tools and dependencies. These are not included here. Inspect the script and pins before running anything against a separate working copy. A successful build of this track would not by itself prove a working Windows client or multiplayer.

## Windows x64 component track

[native/windows-core/toolchain.cmake](../native/windows-core/toolchain.cmake) describes the Windows x64 ABI toolchain inputs used by the work, including LLVM/LLD and Microsoft MSVC and Windows SDK files. Those SDKs, headers, import libraries and redistributables are not shipped here. Obtain and use them under their applicable licenses and redistribution terms. Wine, the graphics stack and their dependencies also need appropriate provenance and license review.

The code contains local diagnostics and pin checks. [native/client-profile/run_current.py](../native/client-profile/run_current.py) references an existing local binding and generated helper; neither is provided as a fresh-install bootstrap. Do not fabricate missing receipts, copy another user's profile or weaken integrity checks to make it start.

The documented 6 November preflight checked an existing local environment only. It did not start a client or demonstrate an end-to-end build from this repository. Do not consider the commands a verified installation or a promise of compatibility.
