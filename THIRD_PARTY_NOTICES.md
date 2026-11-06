# Source provenance and license boundaries

The root No Sale License applies to the project's original independent
contributions only. It must not be applied to someone else's material or used
to restrict rights granted by an upstream license.

## CitizenFX/FiveM

Upstream: https://github.com/citizenfx/fivem

The native patch queue pins its baseline in `config/native-port.json`. The
separate currently examined Windows client generation uses commit
`88a413835e9d7f56633f249880a13f42297153a2`. These baselines are not interchangeable.

The upstream repository license and notices remain applicable to upstream
source, patch context, and derivative changes. In particular, the upstream
license identifies `code/client/shared`, `code/client/citicore`,
`code/client/launcher`, `code/client/common`, `code/tools`,
`code/components/citizen-*`, `code/components/font-renderer`,
`code/components/vfs-core`, and `code/vendor/*.lua` under the GNU Library
General Public License version 2. Other parts and services have their own
terms. Public availability is not a grant to relicense every FiveM component.

Copies are in `LICENSES/FIVEM-UPSTREAM-LICENSE.txt` and `LICENSES/LGPL-2.0.txt`.
The project does not impose its sale restriction on LGPL-covered upstream
material or patches to that material. Preserve upstream notices and comply
with the applicable license when redistributing modified upstream sources.

## DXMT and Wine

Upstream projects:

- https://github.com/3Shain/dxmt
- https://gitlab.winehq.org/wine/wine
- https://www.codeweavers.com/crossover/source

`patches/dxmt` and `patches/wine` contain changes to those projects, with their
upstream context retained. They are not relicensed under the project's sale
restriction. DXMT identifies LGPL-2.1-or-later in its upstream license; Wine's
applicable file and distribution notices must also be preserved. Copies of
the DXMT notice and LGPL-2.1 text are included in `LICENSES/`.

## Other dependencies and notices

`native/windows-client/LICENSE.openssl-enumeration.txt` retains the notice for
the included OpenSSL enumeration material. Other dependencies referenced by
build recipes must be obtained separately under their own licenses. Keeping a
dependency's name or pin here does not redistribute its binaries or grant new
rights to it.

Microsoft Visual C++ and Windows SDK payloads, Wine/GPTK/D3DMetal runtime
packages, official FiveM binaries, Rockstar software, GTA executables and
assets, accounts, credentials, caches, and crash dumps are not included in
this source publication.

The initial two-file repository commit retains its MIT license in
`LICENSES/INITIAL-MIT.txt`. The new project license is prospective and does
not revoke those earlier rights. This repository makes no claim that a
complete, commercially redistributable client package has passed a final
license audit.
