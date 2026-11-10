# Changelog

All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

The Go module path moved from `github.com/tbhb-dev/gomodscan` to `go.tbhb.dev/gomodscan`. The old path isn't deprecated. Releases up to v0.1.0 declare it.

- - -
<!-- release -->

## [v0.2.0](https://github.com/tbhb-dev/gomodscan/compare/a64f5f97ed7f3c39275d7ae3436c02459466c4fa..v0.2.0) - 2026-11-10

### Features

- (**pkgsite**) cache responses on disk by default (#21) - ([5d8487f](https://github.com/tbhb-dev/gomodscan/commit/5d8487fbe574fb47e77eef9a907c15c944678aef)) - [@tbhb](https://github.com/tbhb)
- (**pkgsite**) add retry and backoff to the pkg.go.dev client (#19) - ([a2a6cd3](https://github.com/tbhb-dev/gomodscan/commit/a2a6cd311a2018f9bb252327568b4bd2807c33b0)) - [@tbhb](https://github.com/tbhb)
- ![BREAKING](https://img.shields.io/badge/BREAKING-red) move to tbhb-dev/gomodscan and fail closed on lookup errors (#62) - ([d6e797d](https://github.com/tbhb-dev/gomodscan/commit/d6e797d9befb1b3f4e6c9b4343dcd35db5e0970a)) - tbhb.dev Agent
- add retry and backoff to the OSV client (#20) - ([04c1b6d](https://github.com/tbhb-dev/gomodscan/commit/04c1b6dd663a0bd9ef5b482278b9582fa2f34abb)) - [@tbhb](https://github.com/tbhb)

### Bug Fixes

- (**deps**) update go deps (#80) - ([1d7083e](https://github.com/tbhb-dev/gomodscan/commit/1d7083e6ee351b0b4d7705c9c2346ad45d43127c)) - tbhb-dev-renovate[bot]
- (**pkgsite**) bound Versions against a non-advancing cursor (#41) - ([bb31d24](https://github.com/tbhb-dev/gomodscan/commit/bb31d24d3b97b29b5dc3af6a056ef493af9d3195)) - [@tbhb](https://github.com/tbhb)
- report attempts and status on every lookup failure (#64) - ([5ca6133](https://github.com/tbhb-dev/gomodscan/commit/5ca61337cb054adaa9e7e9ce52df9ae9dd030732)) - tbhb.dev Agent

### Documentation

- (**just**) give every recipe a usable one-line summary - ([562b114](https://github.com/tbhb-dev/gomodscan/commit/562b114ba48c0bed50ec7cbced0a8cde1712d89a)) - [@tbhb](https://github.com/tbhb)
- restate the authorship fields rule (#109) - ([f62d85b](https://github.com/tbhb-dev/gomodscan/commit/f62d85b6a14358c4862b1cce6a16fb546f2d47ee)) - tbhb.dev Agent
- tighten the wording of comments in the scanner and retry code (#70) - ([93da5b9](https://github.com/tbhb-dev/gomodscan/commit/93da5b9c36baf40507ad46d551bd600e6802dd6b)) - tbhb.dev Agent
- fix the build metadata date comment (#32) - ([df1068b](https://github.com/tbhb-dev/gomodscan/commit/df1068b27332579c3bbec5a9e73eb1244116dc0e)) - [@tbhb](https://github.com/tbhb)

### Build system

- (**deps**) bump Go toolchain to go1.26.5 for GO-2026-5856 (#38) - ([080dfde](https://github.com/tbhb-dev/gomodscan/commit/080dfde1731f59ea7c10160c1d0456133c13d595)) - [@tbhb](https://github.com/tbhb)
- (**gitleaks**) run the scan from a digest-pinned image - ([cbde9f8](https://github.com/tbhb-dev/gomodscan/commit/cbde9f8ecd9bc3f712e3c65fdd2ec2d21bb67c6d)) - [@tbhb](https://github.com/tbhb)
- register the hermetic C/C++ toolchain (#111) - ([cf194bd](https://github.com/tbhb-dev/gomodscan/commit/cf194bd3266a09b875a8cad1ca4651f2cfedc3a2)) - tbhb.dev Agent
- bump the tbhb-dev/rules pins to 8944257 (#98) - ([12c9998](https://github.com/tbhb-dev/gomodscan/commit/12c9998cfcf4d831dca23c21fb1f739c845dc15d)) - tbhb.dev Agent
- raise go to 1.26.10 and lift the go-sarif hold (#96) - ([460cfa1](https://github.com/tbhb-dev/gomodscan/commit/460cfa13e4b7fc7998818fefcaecdd9696eacaea)) - tbhb.dev Agent
- move to Bazel and the go.tbhb.dev module path (#91) - ([a68c92b](https://github.com/tbhb-dev/gomodscan/commit/a68c92bc495cede06d10a892980b3881f183cf4a)) - tbhb.dev Agent
- adopt shared `devtools` v0.20.0 (#84) - ([3a9038c](https://github.com/tbhb-dev/gomodscan/commit/3a9038cdff64c40b300484cf8a5d36ee40fc8231)) - tbhb.dev Agent
- adopt devtools v0.14.0 (#61) - ([8cc1423](https://github.com/tbhb-dev/gomodscan/commit/8cc142387fc025baf53db575a1e26ff3ed62a6c4)) - tbhb.dev Agent

### Continuous Integration

- (**deps**) move the github-actions pins to v0.4.0 (#50) - ([5312059](https://github.com/tbhb-dev/gomodscan/commit/53120599bc6c6099a9612aa58ea390805d351cf0)) - [@tbhb](https://github.com/tbhb)
- (**lint**) gate the whole lint set, and add the shell, Justfile-format, and editorconfig recipes (#51) - ([b3cd477](https://github.com/tbhb-dev/gomodscan/commit/b3cd477215d70a08c31f5501cdb0ab6eb49d4650)) - [@tbhb](https://github.com/tbhb)
- (**renovate**) adopt the shared Go preset and inline the global options (#48) - ([8d0915d](https://github.com/tbhb-dev/gomodscan/commit/8d0915d81ad28ae17ee13fd8e85998ba1c4f4e17)) - [@tbhb](https://github.com/tbhb)
- (**renovate**) inline global options to drop anonymous preset fetch (#37) - ([3d9341a](https://github.com/tbhb-dev/gomodscan/commit/3d9341a89e878eecd8bd8246cbb21f071136d5ef)) - [@tbhb](https://github.com/tbhb)
- (**renovate**) use shared presets in this repo config (#26) - ([832478d](https://github.com/tbhb-dev/gomodscan/commit/832478d1d859cfd86cc75f19e29029804c128421)) - [@tbhb](https://github.com/tbhb)
- (**renovate**) track Vale style packages in .vale.ini (#25) - ([a65cf8d](https://github.com/tbhb-dev/gomodscan/commit/a65cf8dd4e0164460ac5535bc79be518a3c114e7)) - [@tbhb](https://github.com/tbhb)
- (**tombi**) add the org config lint and format gate (#49) - ([d532733](https://github.com/tbhb-dev/gomodscan/commit/d532733b1afbdf6900788c179df54c3f04180780)) - [@tbhb](https://github.com/tbhb)
- (**vale**) follow the vale CLI repo move to vale-cli/vale (#40) - ([2296194](https://github.com/tbhb-dev/gomodscan/commit/2296194994bf19b6a5465ca06a46bf47368f0ee7)) - [@tbhb](https://github.com/tbhb)
- advance the github-actions renovate workflow pin to v0.2.2 (#39) - ([07392e4](https://github.com/tbhb-dev/gomodscan/commit/07392e44b5c4f6a569ffe6bf1efa134cb41a0a39)) - [@tbhb](https://github.com/tbhb)
- advance the github-actions pins to v0.2.1 (#31) - ([51bd6a8](https://github.com/tbhb-dev/gomodscan/commit/51bd6a8d81b6910820b09fe7c3ddfd895c5d7b9d)) - [@tbhb](https://github.com/tbhb)
- default vale output to the agent template - ([9e73a60](https://github.com/tbhb-dev/gomodscan/commit/9e73a600195e87c73a0cb2e67fa973046de27744)) - [@tbhb](https://github.com/tbhb)
- adopt the shared proofhouse vale package - ([f855ba0](https://github.com/tbhb-dev/gomodscan/commit/f855ba0b5c828d368fca388a4f087e7a2d94a8c6)) - [@tbhb](https://github.com/tbhb)
- source lint-workflows from the shared github-actions repo (#18) - ([622d295](https://github.com/tbhb-dev/gomodscan/commit/622d295874d4d9d74018d242900f222b849d431a)) - [@tbhb](https://github.com/tbhb)
- source the lint-codeowners workflow from the shared github-actions repo (#17) - ([88c84d8](https://github.com/tbhb-dev/gomodscan/commit/88c84d87b6be71d7717c1969dded47e9ba57e661)) - [@tbhb](https://github.com/tbhb)
- source Renovate workflows from the shared github-actions repo (#13) - ([11002e4](https://github.com/tbhb-dev/gomodscan/commit/11002e460778e0b00b5dbe1eb4750a798349cd52)) - [@tbhb](https://github.com/tbhb)
- source setup-just from the shared github-actions repo (#12) - ([a64f5f9](https://github.com/tbhb-dev/gomodscan/commit/a64f5f97ed7f3c39275d7ae3436c02459466c4fa)) - [@tbhb](https://github.com/tbhb)

### Refactoring

- (**just**) hoist the shared container prefix into a variable - ([fc18f06](https://github.com/tbhb-dev/gomodscan/commit/fc18f0654096f046e6cdce1a1db001dbb4896c2a)) - [@tbhb](https://github.com/tbhb)

### Style

- (**just**) express setup as recipe dependencies - ([4725454](https://github.com/tbhb-dev/gomodscan/commit/47254549cd069e22f99fc293c27ed9b1fb0257ea)) - [@tbhb](https://github.com/tbhb)
- rephrase prose flagged by ai-tells v1.17.1 - ([45bf6e7](https://github.com/tbhb-dev/gomodscan/commit/45bf6e785f269d9cbe9a7ecae899a037fa4e1758)) - [@tbhb](https://github.com/tbhb)

- - -

<!-- release -->

## [v0.1.0](https://github.com/tbhb-dev/gomodscan/compare/4361a6f8e41e7b850ed9854c41a3343e6c1507f6..v0.1.0) - 2026-05-31

### Features

- add gomodscan dependency scanner - ([4361a6f](https://github.com/tbhb-dev/gomodscan/commit/4361a6f8e41e7b850ed9854c41a3343e6c1507f6)) - [@tbhb](https://github.com/tbhb)

#### Bug Fixes

- anchor SARIF results on a physical location for Code Scanning (#1) - ([e17f04d](https://github.com/tbhb-dev/gomodscan/commit/e17f04d80c169f7b768884786538b71882510baf)) - [@tbhb](https://github.com/tbhb)

#### Continuous Integration

- (**actions**) upload per-slot and combined coverage reports (#9) - ([f54ff4b](https://github.com/tbhb-dev/gomodscan/commit/f54ff4bbff2bb149291c36f751ae674d235ffadd)) - [@tbhb](https://github.com/tbhb)
- (**actions**) add CODEOWNERS and a lint-codeowners gate (#8) - ([ca18d35](https://github.com/tbhb-dev/gomodscan/commit/ca18d35bd7f6b1ffd7bce4f26b4f3445c18defaa)) - [@tbhb](https://github.com/tbhb)
- (**actions**) add the mutation-nightly gremlins sweep (#7) - ([3273405](https://github.com/tbhb-dev/gomodscan/commit/32734050404e1b3e1937653ee9b31a6493adcdda)) - [@tbhb](https://github.com/tbhb)
- (**actions**) add the nightly fuzz sweep (#6) - ([c9f116e](https://github.com/tbhb-dev/gomodscan/commit/c9f116e603eb3573333132cc684aa76c530c45ea)) - [@tbhb](https://github.com/tbhb)
- (**actions**) add CodeQL scanning for Go and Actions (#5) - ([3b8e171](https://github.com/tbhb-dev/gomodscan/commit/3b8e17125f3dbb96c7ec99c5a20494d7453079d9)) - [@tbhb](https://github.com/tbhb)
- (**actions**) add the supply chain scanning workflow (#4) - ([2cb4c33](https://github.com/tbhb-dev/gomodscan/commit/2cb4c33bbf1f0007de000c2435dc4224abeab7c1)) - [@tbhb](https://github.com/tbhb)
- skip the Changelog in the vale pre-commit hook - ([380d84f](https://github.com/tbhb-dev/gomodscan/commit/380d84f367fc96871aeda40d1c81bd4b6a5e31fe)) - [@tbhb](https://github.com/tbhb)
- bump the rumdl pre-commit hook to v0.2.4 - ([1a21f3d](https://github.com/tbhb-dev/gomodscan/commit/1a21f3d3e7255110bf8bf42d89b8572bc5acf126)) - [@tbhb](https://github.com/tbhb)
- scope Changelog rule exclusions to rumdl per-path config - ([ad763ba](https://github.com/tbhb-dev/gomodscan/commit/ad763ba79c8a3bf8252b252a493ac8df21507680)) - [@tbhb](https://github.com/tbhb)
- move commit-msg gates to the shared pre-commit-hooks repo (#11) - ([a1fe75f](https://github.com/tbhb-dev/gomodscan/commit/a1fe75fa84ac92a0ffae9a8c4b65412b567d15d1)) - [@tbhb](https://github.com/tbhb)
- resolve the worktree dictionary in the cspell commit-msg hook (#3) - ([2ad2e39](https://github.com/tbhb-dev/gomodscan/commit/2ad2e399ba27627e5fe098fd1a9dd20120322da7)) - [@tbhb](https://github.com/tbhb)
- add self-hosted Renovate config and workflows (#2) - ([930b14a](https://github.com/tbhb-dev/gomodscan/commit/930b14a057573ff3e4bbca371475065ea7d21489)) - [@tbhb](https://github.com/tbhb)
