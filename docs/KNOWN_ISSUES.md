# Known issues

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
- A complete LAN multiplayer session and gameplay have not been demonstrated. An isolated official LAN test server is planned but has not been started; there is no successful result to report.
