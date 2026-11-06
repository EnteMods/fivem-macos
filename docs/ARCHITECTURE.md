# Architecture

The source work has two related tracks. The native ARM64 work uses the patch queue and source pins in [config/native-port.json](../config/native-port.json). The Windows-source client track builds selected public components with a Windows x64 ABI and runs them in a Wine-based environment on macOS. These tracks have different base revisions and are not interchangeable binary sets.

The [native source tree](../native/) contains macOS discovery and protocol handling, Windows CoreRT/client/NUI/launcher work, rendering experiments and bounded diagnostics. [scripts/native_port.py](../scripts/native_port.py) describes the native ARM64 source preparation and build workflow. [patches](../patches/) contains project modifications with upstream context; consult the accompanying license and notices before redistributing derivatives.

The official production client and a source candidate are separate. Local integrity checks bind a candidate to selected inputs; they do not prove a successful join or complete portability. The published source does not include the locally bound profile, build outputs, Wine runtime, user data or production binaries.

The public network client has an authentication interception event and serializes handler-supplied fields. The receiving server requires and verifies its ticket in the normal non-LAN path. That public interface does not identify an authorized independent ticket issuer. Existing Steam, Rockstar and Cfx identity steps must not be conflated.

The public Wine selection and security-related behavior are preserved. Diagnostic observations are bounded to their recorded environment and should not be generalized to other installations or hidden component internals.
