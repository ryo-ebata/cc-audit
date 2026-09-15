# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.22.2](https://github.com/ryo-ebata/cc-audit/compare/v3.22.1...v3.22.2) (2026-09-15)


### Bug Fixes

* **ci:** grant CVE updater write permissions ([#375](https://github.com/ryo-ebata/cc-audit/issues/375)) ([f3f1ef9](https://github.com/ryo-ebata/cc-audit/commit/f3f1ef95316a21770e351b016587d6665af0fbd4))

## [3.22.1](https://github.com/ryo-ebata/cc-audit/compare/v3.22.0...v3.22.1) (2026-09-15)


### Bug Fixes

* **ci:** diagnose CVE app push authorization ([#372](https://github.com/ryo-ebata/cc-audit/issues/372)) ([c5b8432](https://github.com/ryo-ebata/cc-audit/commit/c5b8432785fe3f9d01fa51a5b133dd3ad3b19ee2))

## [3.22.0](https://github.com/ryo-ebata/cc-audit/compare/v3.21.5...v3.22.0) (2026-09-15)


### Features

* **injection:** detect Italian Turkish and Polish overrides ([#363](https://github.com/ryo-ebata/cc-audit/issues/363)) ([df61f20](https://github.com/ryo-ebata/cc-audit/commit/df61f204e4b39a2d838173ceb22845545fc0f1bb))


### Bug Fixes

* **release:** identify crates.io preflight requests ([#365](https://github.com/ryo-ebata/cc-audit/issues/365)) ([f98b477](https://github.com/ryo-ebata/cc-audit/commit/f98b477d3459c695f1a1df3fb6dd2a7ebc68c27d))

## [3.21.5](https://github.com/ryo-ebata/cc-audit/compare/v3.21.4...v3.21.5) (2026-09-15)


### Bug Fixes

* **release:** retry crates.io publishing safely ([#361](https://github.com/ryo-ebata/cc-audit/issues/361)) ([b96eca9](https://github.com/ryo-ebata/cc-audit/commit/b96eca9eb9fb7f9a2183c36b40e21a507e251bc1))

## [3.21.4](https://github.com/ryo-ebata/cc-audit/compare/v3.21.3...v3.21.4) (2026-09-15)


### Performance Improvements

* **skill:** avoid walking scripts twice ([#358](https://github.com/ryo-ebata/cc-audit/issues/358)) ([86a5d20](https://github.com/ryo-ebata/cc-audit/commit/86a5d2072e8cb9751cef9cace7c5f8ac9628db39))

## [3.21.3](https://github.com/ryo-ebata/cc-audit/compare/v3.21.2...v3.21.3) (2026-09-15)


### Bug Fixes

* **ci:** resolve release tags in downstream workflows ([308018c](https://github.com/ryo-ebata/cc-audit/commit/308018ca8f7a461257f051431804e7305e226cfc))

## [3.21.2](https://github.com/ryo-ebata/cc-audit/compare/v3.21.1...v3.21.2) (2026-09-15)


### Bug Fixes

* **ci:** pin Codecov action to verified commit ([#355](https://github.com/ryo-ebata/cc-audit/issues/355)) ([0e7d6c2](https://github.com/ryo-ebata/cc-audit/commit/0e7d6c2af1ad651a557c956b5c38ba2e5509c94b))

## [3.21.1](https://github.com/ryo-ebata/cc-audit/compare/v3.21.0...v3.21.1) (2026-09-15)


### Bug Fixes

* **ignore:** preserve patterns when adding filters ([18bdaab](https://github.com/ryo-ebata/cc-audit/commit/18bdaab2ed3e472a212d99dfc24ae287b382b835))
* **ignore:** preserve patterns when adding filters ([5c1970d](https://github.com/ryo-ebata/cc-audit/commit/5c1970d67e6f6b3570178a0748fa5571ada909d8))

## [3.21.0](https://github.com/ryo-ebata/cc-audit/compare/v3.20.0...v3.21.0) (2026-09-14)


### Features

* **rules:** add Arabic prompt injection detection ([#345](https://github.com/ryo-ebata/cc-audit/issues/345)) ([7a7a52b](https://github.com/ryo-ebata/cc-audit/commit/7a7a52b3bf28e84e7b255cffb3c237951c81757a))

## [3.20.0](https://github.com/ryo-ebata/cc-audit/compare/v3.19.0...v3.20.0) (2026-09-14)


### Features

* **rules:** add German prompt injection detection ([#343](https://github.com/ryo-ebata/cc-audit/issues/343)) ([6e9ff7e](https://github.com/ryo-ebata/cc-audit/commit/6e9ff7e34a5c12246db773219c48b2ded3f74f96))

## [3.19.0](https://github.com/ryo-ebata/cc-audit/compare/v3.18.0...v3.19.0) (2026-09-14)


### Features

* **rules:** add French prompt injection detection ([#341](https://github.com/ryo-ebata/cc-audit/issues/341)) ([f2f0dc4](https://github.com/ryo-ebata/cc-audit/commit/f2f0dc4537068fa919175d98a1130116efd044ee))

## [3.18.0](https://github.com/ryo-ebata/cc-audit/compare/v3.17.30...v3.18.0) (2026-09-14)


### Features

* **rules:** add Hindi prompt injection detection ([#339](https://github.com/ryo-ebata/cc-audit/issues/339)) ([69aefce](https://github.com/ryo-ebata/cc-audit/commit/69aefce35eb3d2bf166e6e249c804e82794dc95a))

## [3.17.30](https://github.com/ryo-ebata/cc-audit/compare/v3.17.29...v3.17.30) (2026-09-14)


### Bug Fixes

* **skill:** scan extended script file types ([#337](https://github.com/ryo-ebata/cc-audit/issues/337)) ([d5bd6de](https://github.com/ryo-ebata/cc-audit/commit/d5bd6dea57c016ae7b15ff0068a0d095d0a63d02))

## [3.17.29](https://github.com/ryo-ebata/cc-audit/compare/v3.17.28...v3.17.29) (2026-09-14)


### Bug Fixes

* **cve:** order prerelease versions below releases ([#335](https://github.com/ryo-ebata/cc-audit/issues/335)) ([a1a8790](https://github.com/ryo-ebata/cc-audit/commit/a1a879072316c26702a0fbfd0fc042032c116207))

## [3.17.28](https://github.com/ryo-ebata/cc-audit/compare/v3.17.27...v3.17.28) (2026-09-14)


### Bug Fixes

* **cve:** restore FrontMCP product names ([#333](https://github.com/ryo-ebata/cc-audit/issues/333)) ([a0f8b40](https://github.com/ryo-ebata/cc-audit/commit/a0f8b40f51a0bda42b9b3b87c0a942bebfef3951))

## [3.17.27](https://github.com/ryo-ebata/cc-audit/compare/v3.17.26...v3.17.27) (2026-09-14)


### Bug Fixes

* **cve:** normalize canonical MCP package names ([#331](https://github.com/ryo-ebata/cc-audit/issues/331)) ([7e5fbe0](https://github.com/ryo-ebata/cc-audit/commit/7e5fbe00340cb953fb9bfe1cfcae9f5c1e2be92c))

## [3.17.26](https://github.com/ryo-ebata/cc-audit/compare/v3.17.25...v3.17.26) (2026-09-14)


### Bug Fixes

* **cve:** ignore unresolved npm version ranges ([#329](https://github.com/ryo-ebata/cc-audit/issues/329)) ([942fdc1](https://github.com/ryo-ebata/cc-audit/commit/942fdc189b98819c0425e275e18ee4c5c1a58e9c))

## [3.17.25](https://github.com/ryo-ebata/cc-audit/compare/v3.17.24...v3.17.25) (2026-09-14)


### Bug Fixes

* **parser:** accept BOM and leading whitespace in frontmatter ([#327](https://github.com/ryo-ebata/cc-audit/issues/327)) ([abbb36a](https://github.com/ryo-ebata/cc-audit/commit/abbb36a3789936455fbf7b0327c0d8bbba3df4c9))

## [3.17.24](https://github.com/ryo-ebata/cc-audit/compare/v3.17.23...v3.17.24) (2026-09-14)


### Bug Fixes

* **runtime:** execute real scans through ScanExecutor ([#325](https://github.com/ryo-ebata/cc-audit/issues/325)) ([778581c](https://github.com/ryo-ebata/cc-audit/commit/778581c89620c1d4953b96dab25f68222ce206c7))

## [3.17.23](https://github.com/ryo-ebata/cc-audit/compare/v3.17.22...v3.17.23) (2026-09-14)


### Bug Fixes

* **remote:** enforce GitCloner repository size limit ([#323](https://github.com/ryo-ebata/cc-audit/issues/323)) ([e6c3c7e](https://github.com/ryo-ebata/cc-audit/commit/e6c3c7ea6ab1298e6963b34f4e67f066cd6b537d))

## [3.17.22](https://github.com/ryo-ebata/cc-audit/compare/v3.17.21...v3.17.22) (2026-09-14)


### Bug Fixes

* **config:** surface malformed project configuration ([#321](https://github.com/ryo-ebata/cc-audit/issues/321)) ([6a21929](https://github.com/ryo-ebata/cc-audit/commit/6a21929c44cd109de27d67fe13742dc0dd007a34))

## [3.17.21](https://github.com/ryo-ebata/cc-audit/compare/v3.17.20...v3.17.21) (2026-09-14)


### Bug Fixes

* **ci:** derive CVE merge checks from ruleset ([#320](https://github.com/ryo-ebata/cc-audit/issues/320)) ([5025bd9](https://github.com/ryo-ebata/cc-audit/commit/5025bd9ed78f894ad13ac12c7d985b5555da2e79))
* **rules:** detect direct wget execution pipelines ([#318](https://github.com/ryo-ebata/cc-audit/issues/318)) ([82c93bd](https://github.com/ryo-ebata/cc-audit/commit/82c93bda6b677eef9f750aa0f77de893d2649dd2))

## [3.17.20](https://github.com/ryo-ebata/cc-audit/compare/v3.17.19...v3.17.20) (2026-09-14)


### Bug Fixes

* **rules:** scope OP-003 test exclusions ([#316](https://github.com/ryo-ebata/cc-audit/issues/316)) ([78c2700](https://github.com/ryo-ebata/cc-audit/commit/78c2700fec07645662bb4afa522435714fc104c3))

## [3.17.19](https://github.com/ryo-ebata/cc-audit/compare/v3.17.18...v3.17.19) (2026-09-14)


### Bug Fixes

* **rules:** detect full environment dumps ([#314](https://github.com/ryo-ebata/cc-audit/issues/314)) ([0c7cc45](https://github.com/ryo-ebata/cc-audit/commit/0c7cc45450603250948b0e79f721b74f6b9e37fa))

## [3.17.18](https://github.com/ryo-ebata/cc-audit/compare/v3.17.17...v3.17.18) (2026-09-14)


### Bug Fixes

* **rules:** detect direct wget docker pipelines ([#312](https://github.com/ryo-ebata/cc-audit/issues/312)) ([5509c30](https://github.com/ryo-ebata/cc-audit/commit/5509c3054114620140e3cb7961a4683f3f93ddeb))

## [3.17.17](https://github.com/ryo-ebata/cc-audit/compare/v3.17.16...v3.17.17) (2026-09-14)


### Bug Fixes

* **rules:** cover chromium browser data paths ([#309](https://github.com/ryo-ebata/cc-audit/issues/309)) ([bb3a3d3](https://github.com/ryo-ebata/cc-audit/commit/bb3a3d34653c912f7c0a9dfd085dd2b71c66d513))
* **rules:** detect decoded payload interpreter pipes ([#311](https://github.com/ryo-ebata/cc-audit/issues/311)) ([a365b3a](https://github.com/ryo-ebata/cc-audit/commit/a365b3a5776ee1fc7c858c5d3063487a3cd795b4))

## [3.17.16](https://github.com/ryo-ebata/cc-audit/compare/v3.17.15...v3.17.16) (2026-09-14)


### Bug Fixes

* **rules:** bound EX-010 fixture exclusions ([#303](https://github.com/ryo-ebata/cc-audit/issues/303)) ([6447b93](https://github.com/ryo-ebata/cc-audit/commit/6447b933ffc6f0839759278ac5126e14b7e2aa69))

## [3.17.15](https://github.com/ryo-ebata/cc-audit/compare/v3.17.14...v3.17.15) (2026-09-14)


### Bug Fixes

* **scanner:** propagate directory scan errors ([#294](https://github.com/ryo-ebata/cc-audit/issues/294)) ([8a2c7da](https://github.com/ryo-ebata/cc-audit/commit/8a2c7da7df278ffc5ef1db35f4679211ece21e06))

## [3.17.14](https://github.com/ryo-ebata/cc-audit/compare/v3.17.13...v3.17.14) (2026-09-14)


### Bug Fixes

* **hook:** close runtime security bypasses ([#287](https://github.com/ryo-ebata/cc-audit/issues/287)) ([fe2cfd5](https://github.com/ryo-ebata/cc-audit/commit/fe2cfd5794a1a9ad829481534f4a240611679372))

## [3.17.13](https://github.com/ryo-ebata/cc-audit/compare/v3.17.12...v3.17.13) (2026-09-14)


### Bug Fixes

* **cve:** match all versions for wildcard affected ranges ([#284](https://github.com/ryo-ebata/cc-audit/issues/284)) ([7b7f039](https://github.com/ryo-ebata/cc-audit/commit/7b7f039235cedb8db36f5959d747d5971e22e482)), closes [#223](https://github.com/ryo-ebata/cc-audit/issues/223)

## [3.17.12](https://github.com/ryo-ebata/cc-audit/compare/v3.17.11...v3.17.12) (2026-09-14)


### Bug Fixes

* **cve:** Update CVE database (+10 entries) [v3.17.12] ([#277](https://github.com/ryo-ebata/cc-audit/issues/277)) ([7d1321d](https://github.com/ryo-ebata/cc-audit/commit/7d1321d64a491eb76ae0738bfb63a4ab10cf116a))

## [3.17.11](https://github.com/ryo-ebata/cc-audit/compare/v3.17.10...v3.17.11) (2026-07-03)


### Bug Fixes

* **cve:** update CVE database (v3.17.11) ([#272](https://github.com/ryo-ebata/cc-audit/issues/272)) ([e2de241](https://github.com/ryo-ebata/cc-audit/commit/e2de24132d5514ced6eb3067286fe620754fdaa7))

## [3.17.10](https://github.com/ryo-ebata/cc-audit/compare/v3.17.9...v3.17.10) (2026-07-02)


### Bug Fixes

* **scanners:** run raw baseline before parse and fail loud on unparseable manifest ([#270](https://github.com/ryo-ebata/cc-audit/issues/270)) ([dcc7a3f](https://github.com/ryo-ebata/cc-audit/commit/dcc7a3fdaf6cea74df3840d241c21d651e49fcbb)), closes [#219](https://github.com/ryo-ebata/cc-audit/issues/219)

## [3.17.9](https://github.com/ryo-ebata/cc-audit/compare/v3.17.8...v3.17.9) (2026-07-02)


### Bug Fixes

* **scanners:** scan plugin manifests independently, no short-circuit ([#268](https://github.com/ryo-ebata/cc-audit/issues/268)) ([af977b1](https://github.com/ryo-ebata/cc-audit/commit/af977b13685d18a7948467f0c5a96dbd44c5a98a)), closes [#227](https://github.com/ryo-ebata/cc-audit/issues/227)

## [3.17.8](https://github.com/ryo-ebata/cc-audit/compare/v3.17.7...v3.17.8) (2026-07-02)


### Bug Fixes

* **discovery:** match file extensions case-insensitively ([#266](https://github.com/ryo-ebata/cc-audit/issues/266)) ([426ca4d](https://github.com/ryo-ebata/cc-audit/commit/426ca4d158dfc94d3038e6bb7447a0bf30e87b4d)), closes [#228](https://github.com/ryo-ebata/cc-audit/issues/228)

## [3.17.7](https://github.com/ryo-ebata/cc-audit/compare/v3.17.6...v3.17.7) (2026-07-02)


### Bug Fixes

* **rules:** drop Bash(...) exclusion that masked co-located unrestricted grants ([#264](https://github.com/ryo-ebata/cc-audit/issues/264)) ([1985827](https://github.com/ryo-ebata/cc-audit/commit/1985827a01beb19eb483aae339a61dbf22ef11dc)), closes [#233](https://github.com/ryo-ebata/cc-audit/issues/233)

## [3.17.6](https://github.com/ryo-ebata/cc-audit/compare/v3.17.5...v3.17.6) (2026-07-02)


### Bug Fixes

* **rules:** stop SC-005/OP-005 exclusions from colliding with code tokens ([#262](https://github.com/ryo-ebata/cc-audit/issues/262)) ([1cdfaf2](https://github.com/ryo-ebata/cc-audit/commit/1cdfaf2f3383bbedff1751eea7485f8191173c7f)), closes [#232](https://github.com/ryo-ebata/cc-audit/issues/232)

## [3.17.5](https://github.com/ryo-ebata/cc-audit/compare/v3.17.4...v3.17.5) (2026-07-02)


### Bug Fixes

* **rules:** SC-001/SC-002 catch `> file && bash file` to any path ([#260](https://github.com/ryo-ebata/cc-audit/issues/260)) ([485d72f](https://github.com/ryo-ebata/cc-audit/commit/485d72fe17039eb6f48316a0b1367d8b22a41203)), closes [#234](https://github.com/ryo-ebata/cc-audit/issues/234)

## [3.17.4](https://github.com/ryo-ebata/cc-audit/compare/v3.17.3...v3.17.4) (2026-07-02)


### Bug Fixes

* **rules:** DEP-002 detects gitlab:/bitbucket:/gist: git shorthands ([#258](https://github.com/ryo-ebata/cc-audit/issues/258)) ([7124c8e](https://github.com/ryo-ebata/cc-audit/commit/7124c8e60069844a6a8257518e69e712eb21a30b)), closes [#236](https://github.com/ryo-ebata/cc-audit/issues/236)

## [3.17.3](https://github.com/ryo-ebata/cc-audit/compare/v3.17.2...v3.17.3) (2026-07-02)


### Bug Fixes

* **rules:** DK-002 detects root via uid:gid form (USER 0:0 / root:root) ([#256](https://github.com/ryo-ebata/cc-audit/issues/256)) ([23d5338](https://github.com/ryo-ebata/cc-audit/commit/23d53383e7fc1f088ec54e4915ee0b011306f55a)), closes [#235](https://github.com/ryo-ebata/cc-audit/issues/235)

## [3.17.2](https://github.com/ryo-ebata/cc-audit/compare/v3.17.1...v3.17.2) (2026-07-02)


### Bug Fixes

* **rules:** make PI-005 tool-name spoofing case-insensitive and fix precedence ([#254](https://github.com/ryo-ebata/cc-audit/issues/254)) ([ec0963c](https://github.com/ryo-ebata/cc-audit/commit/ec0963c2e377a21a4cb8f38604e34b040cd80ddd)), closes [#230](https://github.com/ryo-ebata/cc-audit/issues/230) [#231](https://github.com/ryo-ebata/cc-audit/issues/231)

## [3.17.1](https://github.com/ryo-ebata/cc-audit/compare/v3.17.0...v3.17.1) (2026-07-02)


### Bug Fixes

* **scanners:** detect Dockerfile.&lt;suffix&gt; variants ([#252](https://github.com/ryo-ebata/cc-audit/issues/252)) ([f502605](https://github.com/ryo-ebata/cc-audit/commit/f50260558c10c5d73f53b9b675d5183294f465bf)), closes [#226](https://github.com/ryo-ebata/cc-audit/issues/226)

## [3.17.0](https://github.com/ryo-ebata/cc-audit/compare/v3.16.4...v3.17.0) (2026-07-02)


### Features

* **rules:** extend EX-001 exfil detection beyond curl/wget ([#250](https://github.com/ryo-ebata/cc-audit/issues/250)) ([ec6ee9d](https://github.com/ryo-ebata/cc-audit/commit/ec6ee9d5d77ecaf64bce812459e3d1bd644ff99a)), closes [#218](https://github.com/ryo-ebata/cc-audit/issues/218)

## [3.16.4](https://github.com/ryo-ebata/cc-audit/compare/v3.16.3...v3.16.4) (2026-07-02)


### Bug Fixes

* **rules:** make PE-003 chmod-777 detection flag- and mode-tolerant ([#248](https://github.com/ryo-ebata/cc-audit/issues/248)) ([a9166aa](https://github.com/ryo-ebata/cc-audit/commit/a9166aa7831c49b6f961b9080ddae222fc3fc620)), closes [#217](https://github.com/ryo-ebata/cc-audit/issues/217)

## [3.16.3](https://github.com/ryo-ebata/cc-audit/compare/v3.16.2...v3.16.3) (2026-07-02)


### Bug Fixes

* **rules:** anchor OB-002 comment exclusion to line start ([#246](https://github.com/ryo-ebata/cc-audit/issues/246)) ([7b1fcc2](https://github.com/ryo-ebata/cc-audit/commit/7b1fcc2147efaf066a4315de7da2e6bd33e01220)), closes [#216](https://github.com/ryo-ebata/cc-audit/issues/216)

## [3.16.2](https://github.com/ryo-ebata/cc-audit/compare/v3.16.1...v3.16.2) (2026-07-02)


### Bug Fixes

* **rules:** stop SL-010 from excluding lines containing `password`/`secret` ([#244](https://github.com/ryo-ebata/cc-audit/issues/244)) ([7c689e2](https://github.com/ryo-ebata/cc-audit/commit/7c689e2d3b02563832bf186de2f200023782ea08)), closes [#215](https://github.com/ryo-ebata/cc-audit/issues/215)

## [3.16.1](https://github.com/ryo-ebata/cc-audit/compare/v3.16.0...v3.16.1) (2026-07-02)


### Bug Fixes

* **rules:** anchor SL-* keyword exclusions to word boundaries ([#242](https://github.com/ryo-ebata/cc-audit/issues/242)) ([f3e808f](https://github.com/ryo-ebata/cc-audit/commit/f3e808f40d67cb5682a55edf7f4a47eccb2f47eb)), closes [#214](https://github.com/ryo-ebata/cc-audit/issues/214)

## [3.16.0](https://github.com/ryo-ebata/cc-audit/compare/v3.15.0...v3.16.0) (2026-07-02)


### Features

* **rules:** add Korean (ko) multilingual detection across PI-* family ([9236b9f](https://github.com/ryo-ebata/cc-audit/commit/9236b9feea4084f6382f8d87208f540e7ea708e0))

## [3.15.0](https://github.com/ryo-ebata/cc-audit/compare/v3.14.0...v3.15.0) (2026-07-02)


### Features

* **rules:** extend PI-008 tool-shadowing detection to JA/ZH/ES/RU/PT ([404ff54](https://github.com/ryo-ebata/cc-audit/commit/404ff54308e0da4a864b62da654c51550f3d3042))

## [3.14.0](https://github.com/ryo-ebata/cc-audit/compare/v3.13.1...v3.14.0) (2026-07-02)


### Features

* **rules:** extend multilingual detection to PI-002/PI-007 comments ([#140](https://github.com/ryo-ebata/cc-audit/issues/140)) ([8a2fa6c](https://github.com/ryo-ebata/cc-audit/commit/8a2fa6c0be4449ec86e1f6dea33ce92c3f1f6136))

## [3.13.1](https://github.com/ryo-ebata/cc-audit/compare/v3.13.0...v3.13.1) (2026-07-02)


### Bug Fixes

* **engine:** scan raw MCP content so unmodeled fields can't evade ([#136](https://github.com/ryo-ebata/cc-audit/issues/136)) ([6457050](https://github.com/ryo-ebata/cc-audit/commit/6457050fc76f8fbd57efc084cac7dbc537f1b93a))

## [3.13.0](https://github.com/ryo-ebata/cc-audit/compare/v3.12.0...v3.13.0) (2026-07-02)


### Features

* **rules:** add multilingual detection to PI-001/PI-004 (issue [#140](https://github.com/ryo-ebata/cc-audit/issues/140)) ([bcb8e1e](https://github.com/ryo-ebata/cc-audit/commit/bcb8e1e0987314f644ed22d2987839762a4ce368))

## [3.12.0](https://github.com/ryo-ebata/cc-audit/compare/v3.11.10...v3.12.0) (2026-07-02)


### Features

* **rules:** detect Unicode homoglyph tool-name spoofing (PI-009) ([3226b08](https://github.com/ryo-ebata/cc-audit/commit/3226b08d5e8bad7d2d8b1791128f766a13776a98)), closes [#139](https://github.com/ryo-ebata/cc-audit/issues/139)

## [3.11.10](https://github.com/ryo-ebata/cc-audit/compare/v3.11.9...v3.11.10) (2026-07-02)


### Bug Fixes

* **rules:** remove PI-003 exclusions that enabled a one-word bypass ([ae34d8b](https://github.com/ryo-ebata/cc-audit/commit/ae34d8bf7fa653ffa92bd403df186fad2ae4f867)), closes [#130](https://github.com/ryo-ebata/cc-audit/issues/130)

## [3.11.9](https://github.com/ryo-ebata/cc-audit/compare/v3.11.8...v3.11.9) (2026-07-02)


### Bug Fixes

* **malware:** join line-continuations before signature matching ([#151](https://github.com/ryo-ebata/cc-audit/issues/151)) ([d1be672](https://github.com/ryo-ebata/cc-audit/commit/d1be672a4eefc6ec9ed39e226568c7826557e378))

## [3.11.8](https://github.com/ryo-ebata/cc-audit/compare/v3.11.7...v3.11.8) (2026-07-02)


### Bug Fixes

* **engine:** join shell line-continuations before rule matching ([#126](https://github.com/ryo-ebata/cc-audit/issues/126)) ([b14b195](https://github.com/ryo-ebata/cc-audit/commit/b14b19501f27b25d6b96f7ed7a3ecb9ebcf0dc37))

## [3.11.7](https://github.com/ryo-ebata/cc-audit/compare/v3.11.6...v3.11.7) (2026-07-02)


### Bug Fixes

* **scanner:** default check fans out across all scanners ([#155](https://github.com/ryo-ebata/cc-audit/issues/155)) ([610ffd6](https://github.com/ryo-ebata/cc-audit/commit/610ffd61dd7beaaa6735e9e7c767c01ec7aae45e))

## [3.11.6](https://github.com/ryo-ebata/cc-audit/compare/v3.11.5...v3.11.6) (2026-07-02)


### Bug Fixes

* **hook:** scan Write/Edit content for reverse-shell & installer payloads ([a2c7bba](https://github.com/ryo-ebata/cc-audit/commit/a2c7bba74d8717954780ec60836f163fbf89b362)), closes [#165](https://github.com/ryo-ebata/cc-audit/issues/165)

## [3.11.5](https://github.com/ryo-ebata/cc-audit/compare/v3.11.4...v3.11.5) (2026-07-02)


### Bug Fixes

* **hook:** route reverse-shell & credential-exfil critical patterns into runtime Bash guard ([f0dc538](https://github.com/ryo-ebata/cc-audit/commit/f0dc538424b22c88fd5ffa91a7c30902e1ac9362)), closes [#159](https://github.com/ryo-ebata/cc-audit/issues/159)

## [3.11.4](https://github.com/ryo-ebata/cc-audit/compare/v3.11.3...v3.11.4) (2026-07-02)


### Bug Fixes

* **hook:** close SC-001 trusted-domain bypasses in hook mode ([7930eb6](https://github.com/ryo-ebata/cc-audit/commit/7930eb64c1210d3656a6bd81bd06405fb17c7130)), closes [#158](https://github.com/ryo-ebata/cc-audit/issues/158)

## [3.11.3](https://github.com/ryo-ebata/cc-audit/compare/v3.11.2...v3.11.3) (2026-07-02)


### Bug Fixes

* **rules:** ignore in-band suppression directives by default ([be18135](https://github.com/ryo-ebata/cc-audit/commit/be181358c57c9ff2a14b2c23283bd70f9d944163)), closes [#156](https://github.com/ryo-ebata/cc-audit/issues/156)

## [3.11.2](https://github.com/ryo-ebata/cc-audit/compare/v3.11.1...v3.11.2) (2026-07-02)


### Bug Fixes

* **engine:** cap per-file read size to prevent OOM DoS ([a641e1f](https://github.com/ryo-ebata/cc-audit/commit/a641e1fbb0622fcc62eee72a33bb96024c704b0d)), closes [#143](https://github.com/ryo-ebata/cc-audit/issues/143)

## [3.11.1](https://github.com/ryo-ebata/cc-audit/compare/v3.11.0...v3.11.1) (2026-07-02)


### Bug Fixes

* **cve:** match npm packages by product name; parse real lockfiles (closes [#149](https://github.com/ryo-ebata/cc-audit/issues/149), closes [#153](https://github.com/ryo-ebata/cc-audit/issues/153)) ([216d409](https://github.com/ryo-ebata/cc-audit/commit/216d4098574f51ae562d70080c74c3d3ec58a282))
* **deobfuscation:** iteratively decode nested encodings in deep scan (closes [#128](https://github.com/ryo-ebata/cc-audit/issues/128)) ([8a81b1d](https://github.com/ryo-ebata/cc-audit/commit/8a81b1d03f408223de34c238099b5cc5a793da75))
* **discovery:** scan extension-less scripts via shebang detection ([8264ebc](https://github.com/ryo-ebata/cc-audit/commit/8264ebc290a6d166428769cd901a51e4104f626a)), closes [#152](https://github.com/ryo-ebata/cc-audit/issues/152)
* **engine:** lossy-decode non-UTF-8 files instead of failing open (closes [#129](https://github.com/ryo-ebata/cc-audit/issues/129)) ([5eb1004](https://github.com/ryo-ebata/cc-audit/commit/5eb100478df7225e9653a31acba1c020aa5054b2))
* **engine:** scan all hook events, not just four (closes [#133](https://github.com/ryo-ebata/cc-audit/issues/133)) ([3a9b6e8](https://github.com/ryo-ebata/cc-audit/commit/3a9b6e877a5036834058aa17ce4f55399e2ebe8e))
* **engine:** scan command frontmatter for OP-001 wildcard tools (closes [#135](https://github.com/ryo-ebata/cc-audit/issues/135)) ([7719d7e](https://github.com/ryo-ebata/cc-audit/commit/7719d7eceae2c36c234315c55d6507b72fe40076))
* **parser:** match frontmatter delimiters on their own line (closes [#131](https://github.com/ryo-ebata/cc-audit/issues/131)) ([4a226ed](https://github.com/ryo-ebata/cc-audit/commit/4a226ed7f546a329dd99578d4279b9c559e47b7e))

## [3.11.0](https://github.com/ryo-ebata/cc-audit/compare/v3.10.1...v3.11.0) (2026-07-02)


### Features

* **rules:** detect Slack API tokens in SL-007 (closes [#144](https://github.com/ryo-ebata/cc-audit/issues/144)) ([1d7061e](https://github.com/ryo-ebata/cc-audit/commit/1d7061eb02318a0f6b9baccca1f7d3e9332853f0))

## [3.10.1](https://github.com/ryo-ebata/cc-audit/compare/v3.10.0...v3.10.1) (2026-07-02)


### Bug Fixes

* **deobfuscation:** decode URL-safe and unpadded Base64 in deep scan ([7af3b48](https://github.com/ryo-ebata/cc-audit/commit/7af3b4823c350ae9bcef8bf945df3415ade3ad86)), closes [#127](https://github.com/ryo-ebata/cc-audit/issues/127)
* **engine:** scan MCP remote server headers for hardcoded secrets ([be0abbb](https://github.com/ryo-ebata/cc-audit/commit/be0abbb36a3aace8d04062f6f4886f61d61aad07)), closes [#132](https://github.com/ryo-ebata/cc-audit/issues/132)

## [3.10.0](https://github.com/ryo-ebata/cc-audit/compare/v3.9.0...v3.10.0) (2026-07-02)


### Features

* **rules:** add DEP-011 prepare/prepublish lifecycle script detection ([9672687](https://github.com/ryo-ebata/cc-audit/commit/967268795b163d42e6d16ca6f9a6d92046e0aa54)), closes [#137](https://github.com/ryo-ebata/cc-audit/issues/137)

## [3.9.0](https://github.com/ryo-ebata/cc-audit/compare/v3.8.0...v3.9.0) (2026-07-02)


### Features

* **rules:** add PE-011 container escape + SC-009 Go module integrity bypass ([a3bce82](https://github.com/ryo-ebata/cc-audit/commit/a3bce829342d412b3d45a2a18cbbd44071ec0dc9))

## [3.8.0](https://github.com/ryo-ebata/cc-audit/compare/v3.7.0...v3.8.0) (2026-07-02)


### Features

* **rules:** add EX-020 markdown image exfil + DK-009 Dockerfile secret ([c86e2b3](https://github.com/ryo-ebata/cc-audit/commit/c86e2b301b6437fc9b159256ae024352cc6bf823))

## [3.7.0](https://github.com/ryo-ebata/cc-audit/compare/v3.6.0...v3.7.0) (2026-07-02)


### Features

* **rules:** add EX-019 scripting reverse shell + PS-012 system shell init ([9f24612](https://github.com/ryo-ebata/cc-audit/commit/9f24612964025887814e661e10991aab249eb96f))


### Bug Fixes

* **cve:** update CVE database (v3.6.1) ([#124](https://github.com/ryo-ebata/cc-audit/issues/124)) ([8b378aa](https://github.com/ryo-ebata/cc-audit/commit/8b378aae6a7a9641f0a52b7ac58edd2401faa3ce))

## [3.6.0](https://github.com/ryo-ebata/cc-audit/compare/v3.5.0...v3.6.0) (2026-07-01)


### Features

* **rules:** add EX-018 cloud metadata + PE-009 linker hijacking ([50c1ce2](https://github.com/ryo-ebata/cc-audit/commit/50c1ce25dbf9a9527937414458cef05f20cab958))
* **rules:** add PE-010 PATH hijacking + OB-009 IFS obfuscation ([c922dfe](https://github.com/ryo-ebata/cc-audit/commit/c922dfe9a0f090d1e3690a8ead2e0482e69fe799))

## [3.5.0](https://github.com/ryo-ebata/cc-audit/compare/v3.4.0...v3.5.0) (2026-07-01)


### Features

* **rules:** add EX-017, SL-011; harden SC-003 pip index coverage ([45f4827](https://github.com/ryo-ebata/cc-audit/commit/45f4827a2e1d58d1243155aec04d5c5ce02c8c6c))

## [3.4.0](https://github.com/ryo-ebata/cc-audit/compare/v3.3.0...v3.4.0) (2026-07-01)


### Features

* **rules:** add EX-016, PI-008, PE-008 detection rules ([a668cc7](https://github.com/ryo-ebata/cc-audit/commit/a668cc7353cc8123eaa01c93a198c59238b4a2cb))

## [3.3.0](https://github.com/ryo-ebata/cc-audit/compare/v3.2.14...v3.3.0) (2026-07-01)


### Features

* **rules:** add PS-010, PS-011, EX-015 detection rules ([b802cfe](https://github.com/ryo-ebata/cc-audit/commit/b802cfef05a2df401de55ee5bc337dde45c44b47))


### Bug Fixes

* **xtask:** support multi-line rules() vec in new-rule ([780be7e](https://github.com/ryo-ebata/cc-audit/commit/780be7e7230e3cf0adc3cb1bcec0018489e668b0))

## [3.2.14](https://github.com/ryo-ebata/cc-audit/compare/v3.2.13...v3.2.14) (2026-02-02)


### Bug Fixes

* **robustness:** log WalkDir errors instead of silently swallowing ([#79](https://github.com/ryo-ebata/cc-audit/issues/79)) ([5152b0a](https://github.com/ryo-ebata/cc-audit/commit/5152b0a8c530fecdf78a291f59649b569ad79462)), closes [#9](https://github.com/ryo-ebata/cc-audit/issues/9)

## [3.2.13](https://github.com/ryo-ebata/cc-audit/compare/v3.2.12...v3.2.13) (2026-02-02)


### Bug Fixes

* **deprecation:** correct since version on scanner module ([#76](https://github.com/ryo-ebata/cc-audit/issues/76)) ([a8bb6fc](https://github.com/ryo-ebata/cc-audit/commit/a8bb6fc3df714519e0af5aa2e1c505470bf8a4d5)), closes [#6](https://github.com/ryo-ebata/cc-audit/issues/6)

## [3.2.12](https://github.com/ryo-ebata/cc-audit/compare/v3.2.11...v3.2.12) (2026-02-01)


### Bug Fixes

* **ci:** fix security workflow permissions and CVE update timeout ([#83](https://github.com/ryo-ebata/cc-audit/issues/83)) ([d76b5ee](https://github.com/ryo-ebata/cc-audit/commit/d76b5eec477b0a17465a2116a3607c0b093b08cb))

## [3.2.11](https://github.com/ryo-ebata/cc-audit/compare/v3.2.10...v3.2.11) (2026-02-01)


### Bug Fixes

* **deps:** migrate from deprecated serde_yaml to serde_yml ([#75](https://github.com/ryo-ebata/cc-audit/issues/75)) ([98c0b92](https://github.com/ryo-ebata/cc-audit/commit/98c0b923e5404ad6b838cc2515457dd31d165884))

## [3.2.10](https://github.com/ryo-ebata/cc-audit/compare/v3.2.9...v3.2.10) (2026-02-01)


### Bug Fixes

* **security:** replace panicking unwrap() in MCP server and token sanitization ([#74](https://github.com/ryo-ebata/cc-audit/issues/74)) ([7a224f2](https://github.com/ryo-ebata/cc-audit/commit/7a224f22cdc019187d09e46c9706a921f8befcf9))

## [3.2.9](https://github.com/ryo-ebata/cc-audit/compare/v3.2.8...v3.2.9) (2026-02-01)


### Bug Fixes

* **lint:** add clippy config and fix non-idiomatic patterns ([#73](https://github.com/ryo-ebata/cc-audit/issues/73)) ([5e6f8ba](https://github.com/ryo-ebata/cc-audit/commit/5e6f8ba412f122052b2bcadf55defd9111fa13d5))

## [3.2.8](https://github.com/ryo-ebata/cc-audit/compare/v3.2.7...v3.2.8) (2026-02-01)


### Bug Fixes

* **perf:** add elapsed_ms timing to scan results ([#71](https://github.com/ryo-ebata/cc-audit/issues/71)) ([c04d3f7](https://github.com/ryo-ebata/cc-audit/commit/c04d3f73f926c5b258ec07e0420cefa39f97a6a9))

## [3.2.7](https://github.com/ryo-ebata/cc-audit/compare/v3.2.6...v3.2.7) (2026-01-29)


### Bug Fixes

* **performance:** Phase 1+2 - parallel scanners, directory walker, and deobfuscation ([#68](https://github.com/ryo-ebata/cc-audit/issues/68)) ([083a44f](https://github.com/ryo-ebata/cc-audit/commit/083a44fbf5e08864f2bb1e991601c16861ecc8ec))

## [3.2.6](https://github.com/ryo-ebata/cc-audit/compare/v3.2.5...v3.2.6) (2026-01-29)


### Bug Fixes

* **docs:** add comprehensive comments and fix architecture violations ([#66](https://github.com/ryo-ebata/cc-audit/issues/66)) ([8bd7cc2](https://github.com/ryo-ebata/cc-audit/commit/8bd7cc2aeff8b1eb835eeb44c692f5552ffb8868))

## [3.2.5](https://github.com/ryo-ebata/cc-audit/compare/v3.2.4...v3.2.5) (2026-01-29)


### Bug Fixes

* **performance:** parallelize file scanning with Rayon ([#64](https://github.com/ryo-ebata/cc-audit/issues/64)) ([a47c6a0](https://github.com/ryo-ebata/cc-audit/commit/a47c6a0cc775ac9d8174d775724ff6c99885f911))

## [3.2.4](https://github.com/ryo-ebata/cc-audit/compare/v3.2.3...v3.2.4) (2026-01-29)


### Bug Fixes

* **ux:** improve Japanese text, minified files, long lines, and progress bar ([#61](https://github.com/ryo-ebata/cc-audit/issues/61)) ([f76b44b](https://github.com/ryo-ebata/cc-audit/commit/f76b44b245492f52733cd51abb517d4ce730dd16))

## [3.2.3](https://github.com/ryo-ebata/cc-audit/compare/v3.2.2...v3.2.3) (2026-01-29)


### Bug Fixes

* **config:** change ignore patterns from regex to glob ([#59](https://github.com/ryo-ebata/cc-audit/issues/59)) ([3d941b4](https://github.com/ryo-ebata/cc-audit/commit/3d941b4502392e5b3cefa5a6419db1dacb0fe81d))

## [3.2.2](https://github.com/ryo-ebata/cc-audit/compare/v3.2.1...v3.2.2) (2026-01-29)


### Bug Fixes

* **config:** canonicalize project root path for proper parent directory traversal ([#57](https://github.com/ryo-ebata/cc-audit/issues/57)) ([bb0d842](https://github.com/ryo-ebata/cc-audit/commit/bb0d842502a85e959adeff607f64ce6aee3693eb))

## [3.2.1](https://github.com/ryo-ebata/cc-audit/compare/v3.2.0...v3.2.1) (2026-01-28)


### Bug Fixes

* **test:** strengthen scanner tests to verify detection accuracy ([#55](https://github.com/ryo-ebata/cc-audit/issues/55)) ([f06f72c](https://github.com/ryo-ebata/cc-audit/commit/f06f72cec074bbb7b8746a45fa3f637fe9ea6f50))

## [3.2.0](https://github.com/ryo-ebata/cc-audit/compare/v3.1.7...v3.2.0) (2026-01-28)


### Features

* refactor CLI to subcommand-based structure ([#53](https://github.com/ryo-ebata/cc-audit/issues/53)) ([b3d3d80](https://github.com/ryo-ebata/cc-audit/commit/b3d3d80a767d50a8996f7506805195d72f34a524))

## [3.1.7](https://github.com/ryo-ebata/cc-audit/compare/v3.1.6...v3.1.7) (2026-01-28)


### Bug Fixes

* implement recursive setting in scanner configuration ([#50](https://github.com/ryo-ebata/cc-audit/issues/50)) ([4ff8ffa](https://github.com/ryo-ebata/cc-audit/commit/4ff8ffa645e42f07d5edde2720cfc2d9b7ded9d4))

## [3.1.6](https://github.com/ryo-ebata/cc-audit/compare/v3.1.5...v3.1.6) (2026-01-27)


### Bug Fixes

* respect config file settings in all handlers ([#47](https://github.com/ryo-ebata/cc-audit/issues/47)) ([b76ae4c](https://github.com/ryo-ebata/cc-audit/commit/b76ae4c1353d648371918cadf12bd153d0d51d17))

## [3.1.5](https://github.com/ryo-ebata/cc-audit/compare/v3.1.4...v3.1.5) (2026-01-27)


### Bug Fixes

* **deps:** update criterion from 0.5 to 0.8 ([#45](https://github.com/ryo-ebata/cc-audit/issues/45)) ([07549ec](https://github.com/ryo-ebata/cc-audit/commit/07549ec6400e086bee954e6da85d3897a13047c9))

## [3.1.4](https://github.com/ryo-ebata/cc-audit/compare/v3.1.3...v3.1.4) (2026-01-27)


### Bug Fixes

* **terminal:** improve error display with lint-style output format ([#43](https://github.com/ryo-ebata/cc-audit/issues/43)) ([d36885e](https://github.com/ryo-ebata/cc-audit/commit/d36885e62c671b7fdae39a96baa70de4417e8fee))

## [3.1.4](https://github.com/ryo-ebata/cc-audit/compare/v3.1.3...v3.1.4) (2026-01-27)


### Bug Fixes

* **terminal:** improve error display with lint-style output format

Add lint-style output format similar to ESLint, Clippy for better readability:
- Shows code with line number gutter and caret pointer (^)
- Structured labels: why, ref, fix, example
- Add --compact option for traditional output format
- Document new output format in CLI.md and CLI.ja.md

## [3.1.3](https://github.com/ryo-ebata/cc-audit/compare/v3.1.2...v3.1.3) (2026-01-27)


### Bug Fixes

* **cve:** Update CVE database (+5 entries) [v3.1.3] ([#39](https://github.com/ryo-ebata/cc-audit/issues/39)) ([bc1fba1](https://github.com/ryo-ebata/cc-audit/commit/bc1fba1605c718b136938af9777e4cbd0f15e54c))

## [3.1.2](https://github.com/ryo-ebata/cc-audit/compare/v3.1.1...v3.1.2) (2026-01-27)


### Bug Fixes

* improve detection rules and reduce false positives/negatives ([#40](https://github.com/ryo-ebata/cc-audit/issues/40)) ([72f5edb](https://github.com/ryo-ebata/cc-audit/commit/72f5edb4988d315af0514f094d2c324020d3011e))

## [3.1.1](https://github.com/ryo-ebata/cc-audit/compare/v3.1.0...v3.1.1) (2026-01-26)


### Bug Fixes

* 誤検知(False Positive)の削減 ([#35](https://github.com/ryo-ebata/cc-audit/issues/35)) ([8303692](https://github.com/ryo-ebata/cc-audit/commit/83036923cbb66129e63826c48679faae2e98552f))

## [3.1.0](https://github.com/ryo-ebata/cc-audit/compare/v3.0.0...v3.1.0) (2026-01-26)


### Features

* release v3.1.0 ([#33](https://github.com/ryo-ebata/cc-audit/issues/33)) ([a5cfdee](https://github.com/ryo-ebata/cc-audit/commit/a5cfdeefcc41bbbbab56e7c8de231d724844e126))

## [3.0.0](https://github.com/ryo-ebata/cc-audit/compare/v2.0.0...v3.0.0) (2026-01-26)


### ⚠ BREAKING CHANGES

* Major architecture refactoring with module reorganization.
* Default behavior now returns exit code 1 for ANY finding. Previously only critical/high findings caused CI failure.

### Features

* add comprehensive configuration, HTML reports, baseline drift detection, and scoring system ([c2d2ddb](https://github.com/ryo-ebata/cc-audit/commit/c2d2ddb7ddaa39e47d476b12316a608932e81e49))
* add comprehensive configuration, HTML reports, baseline drift detection, and scoring system ([5cf067a](https://github.com/ryo-ebata/cc-audit/commit/5cf067a72cce56b2a468ef8cacd41a1c22d50554))
* add comprehensive security scanning features for v0.2.0 ([8c9b8cd](https://github.com/ryo-ebata/cc-audit/commit/8c9b8cd6665410a33e2b6b040f0f421f11c3f0db))
* add comprehensive security scanning features for v0.2.0 ([18b421c](https://github.com/ryo-ebata/cc-audit/commit/18b421c1f3718b3248b19512df23ac73ca4d9e1a))
* add multi-client support and CVE vulnerability scanning ([0b351fc](https://github.com/ryo-ebata/cc-audit/commit/0b351fc2333a54546a4a08b61c96beff85fb295f))
* add multi-platform distribution support ([f9b437c](https://github.com/ryo-ebata/cc-audit/commit/f9b437ca16e78b798a49f142ad9a8fdd1c80f5c4))
* add multi-platform distribution support ([70c78ae](https://github.com/ryo-ebata/cc-audit/commit/70c78aec263cca74aa7847d1bfbc0bacd9fa0f2d))
* add rule severity configuration for CI exit code control ([efe8802](https://github.com/ryo-ebata/cc-audit/commit/efe880214bf89bd5b0b3da1f6b0595544d3c4281))
* add snapshot testing infrastructure and git hooks for CI parity ([74f7589](https://github.com/ryo-ebata/cc-audit/commit/74f75893e5f33a0b578232911f39bb16d47de79c))
* add Terraform configuration for GitHub repository protection ([13c9c9c](https://github.com/ryo-ebata/cc-audit/commit/13c9c9c2861584a469d05b52dedea39de4de01a7))
* add Terraform configuration for GitHub repository protection ([736e450](https://github.com/ryo-ebata/cc-audit/commit/736e450d641bd0e9557398ff2e62a6f9faca90e3))
* add v0.4.0 major features - auto-fix, deobfuscation, MCP server, plugin/subagent scanning ([22db6bf](https://github.com/ryo-ebata/cc-audit/commit/22db6bf7efbc9c9ef860e55d23868dd0792f982a))
* CI automation, rule severity, and documentation improvements ([a3047b8](https://github.com/ryo-ebata/cc-audit/commit/a3047b8f74b26d9b2cbd6918ef49a398cf46754e))
* implement 7-layer architecture refactoring ([c8026b0](https://github.com/ryo-ebata/cc-audit/commit/c8026b0d79d4caa0b661e0444045da9eaa8ce23f))
* implement 7-layer architecture refactoring with improved test coverage ([0ff70aa](https://github.com/ryo-ebata/cc-audit/commit/0ff70aa7139fe22284711725927e73e5ceebd2c9))
* initial project setup with v0.2.0 implementation ([31bcdb1](https://github.com/ryo-ebata/cc-audit/commit/31bcdb1603431e8dd3230d289616f9dfc1ca6234))


### Bug Fixes

* add cross-platform support for git hook permissions ([e758006](https://github.com/ryo-ebata/cc-audit/commit/e758006f160b19819413cca3e0291e71f6d662db))
* add last-release-sha to reset release-please versioning ([#24](https://github.com/ryo-ebata/cc-audit/issues/24)) ([678e707](https://github.com/ryo-ebata/cc-audit/commit/678e707c2b5484e27bc26d56dcb04a198bcccd01))
* **ci:** add GITHUB_TOKEN to tfsec-action to prevent rate limiting ([acc4788](https://github.com/ryo-ebata/cc-audit/commit/acc4788b9aa0ac66f6cc2f337166ca9020fdbc3a))
* **ci:** add Self Audit Result job for required status check ([817cf74](https://github.com/ryo-ebata/cc-audit/commit/817cf7481e812ff27057bd775d22b7a0b971e722))
* **ci:** allow uppercase in commit subject ([18e4d9f](https://github.com/ryo-ebata/cc-audit/commit/18e4d9f70cfcc8689ea6193c1d99e31f8ccda090))
* **ci:** use explicit SHA instead of git checkout - in benchmark comparison ([61f69f2](https://github.com/ryo-ebata/cc-audit/commit/61f69f288bf97f8178a2bb46f76096b512d67a19))
* **ci:** use fetch-depth 0 and proper branch checkout for benchmark comparison ([efcf001](https://github.com/ryo-ebata/cc-audit/commit/efcf0012709743951802e4a25350f3d8fec2072f))
* **ci:** use PAT for release-please to bypass GITHUB_TOKEN restrictions ([71513ad](https://github.com/ryo-ebata/cc-audit/commit/71513ad04aefbb6414281a236d544d5871bd078e))
* correct version to 1.1.0 (was incorrectly released as 2.0.0) ([07e4bf9](https://github.com/ryo-ebata/cc-audit/commit/07e4bf9a7b5944ea47965220a839bb4327df7954))
* **infra:** make required_status_checks block conditional ([f2b37b6](https://github.com/ryo-ebata/cc-audit/commit/f2b37b6962134f414048d72d35a58b4dfbd014d9))
* **infra:** remove default required status checks ([983e67c](https://github.com/ryo-ebata/cc-audit/commit/983e67ca7f653ea25e5606307b9dcd9060b00fa9))
* **release:** force release version to 1.2.0 ([#28](https://github.com/ryo-ebata/cc-audit/issues/28)) ([9fe9e61](https://github.com/ryo-ebata/cc-audit/commit/9fe9e61607a09cebd38b99e6cd7b011ddb31b1e5))
* upgrade notify v7 to v8 to resolve RUSTSEC-2024-0384 ([aca5eca](https://github.com/ryo-ebata/cc-audit/commit/aca5eca8a305e73916b575d22ac1ee680655f00c))

## [1.1.0](https://github.com/ryo-ebata/cc-audit/compare/v1.0.0...v1.1.0) (2026-01-26)


### Features

* add multi-client support and CVE vulnerability scanning ([0b351fc](https://github.com/ryo-ebata/cc-audit/commit/0b351fc2333a54546a4a08b61c96beff85fb295f))

## [1.0.0](https://github.com/ryo-ebata/cc-audit/compare/v0.4.1...v1.0.0) (2026-01-25)


### ⚠ BREAKING CHANGES

* Default behavior now returns exit code 1 for ANY finding. Previously only critical/high findings caused CI failure.

### Features

* add rule severity configuration for CI exit code control ([efe8802](https://github.com/ryo-ebata/cc-audit/commit/efe880214bf89bd5b0b3da1f6b0595544d3c4281))
* CI automation, rule severity, and documentation improvements ([a3047b8](https://github.com/ryo-ebata/cc-audit/commit/a3047b8f74b26d9b2cbd6918ef49a398cf46754e))


### Bug Fixes

* **ci:** add Self Audit Result job for required status check ([817cf74](https://github.com/ryo-ebata/cc-audit/commit/817cf7481e812ff27057bd775d22b7a0b971e722))
* **ci:** allow uppercase in commit subject ([18e4d9f](https://github.com/ryo-ebata/cc-audit/commit/18e4d9f70cfcc8689ea6193c1d99e31f8ccda090))
* **ci:** use explicit SHA instead of git checkout - in benchmark comparison ([61f69f2](https://github.com/ryo-ebata/cc-audit/commit/61f69f288bf97f8178a2bb46f76096b512d67a19))
* **ci:** use fetch-depth 0 and proper branch checkout for benchmark comparison ([efcf001](https://github.com/ryo-ebata/cc-audit/commit/efcf0012709743951802e4a25350f3d8fec2072f))
* **ci:** use PAT for release-please to bypass GITHUB_TOKEN restrictions ([71513ad](https://github.com/ryo-ebata/cc-audit/commit/71513ad04aefbb6414281a236d544d5871bd078e))

## [Unreleased]

### Added
- **Multi-Client Support**: Auto-detect and scan AI coding client configurations
  - Supported clients: Claude Code, Cursor, Windsurf, VS Code
  - `--all-clients`: Scan all installed clients
  - `--client <name>`: Scan a specific client (claude, cursor, windsurf, vscode)
  - Findings now include client attribution in output
- **CVE Vulnerability Scanning**: Built-in database of known CVEs affecting MCP and AI tools
  - Scans for 7 known CVEs (CVE-2025-52882, CVE-2025-49596, CVE-2025-54135, etc.)
  - Checks package.json, mcp.json, and extensions.json for vulnerable versions
  - `--cve-db <path>`: Use a custom CVE database
  - `--no-cve-scan`: Disable CVE scanning

### Changed
- `src/client.rs`: New module for client detection
- `src/cve_db.rs`: New module for CVE database handling
- `data/cve-database.json`: Built-in CVE database with 7 entries
- Finding struct now includes optional `client` field

## [0.5.0] - 2026-01-25

### Added
- **Rule Severity Levels**: New `RuleSeverity` (error/warn) to control CI exit codes independently of detection severity
- **Severity Configuration**: Configure per-rule severity in `.cc-audit.yaml`:
  ```yaml
  severity:
    default: error
    warn:
      - PI-001  # Report but don't fail CI
    ignore:
      - OP-001  # Completely skip
  ```
- **New CLI Options**:
  - `--warn-only`: Treat all findings as warnings (exit 0) - useful for initial baseline scans
  - `--min-severity <level>`: Filter findings by severity (critical/high/medium/low)
  - `--min-rule-severity <level>`: Filter by rule severity (error/warn)
- **Enhanced Output**: Terminal output now shows `[ERROR]`/`[WARN]` labels per finding
- **Summary with errors/warnings**: Summary line now shows error and warning counts

### Changed
- **BREAKING**: Default behavior now returns exit code 1 for ANY finding (previously only critical/high)
  - Migration: Use `--warn-only` to restore previous behavior
- **BREAKING**: Summary's `passed` field is now based on `errors == 0` instead of `critical == 0 && high == 0`
- **SARIF Output**: Level now reflects rule severity (error/warning) instead of detection severity
- **JSON Output**: Findings now include `rule_severity` field
- Summary now includes `errors` and `warnings` counts

### Fixed
- Integration tests updated for new exit code behavior

## [0.4.1] - 2026-01-25

### Fixed
- Updated SECURITY.md with correct vulnerability reporting process
- Updated SECURITY.md supported versions to reflect current release

### Changed
- CHANGELOG.md now includes v0.4.0 release notes

## [0.4.0] - 2026-01-25

### Added
- Baseline/Drift detection for rug pull attack prevention (`--baseline`, `--check-drift`, `--save-baseline`, `--baseline-file`)
- Auto-fix functionality (`--fix`, `--fix-dry-run`)
- Deep scan with deobfuscation (`--deep-scan`)
- MCP server mode (`--mcp-server`)
- Profile management (`--profile`, `--save-profile`)
- HTML output format (`--format html`)
- Path comparison (`--compare`)
- Subagent scanning (`--type subagent`)
- Plugin/marketplace scanning (`--type plugin`)
- Risk scoring system (0-100 scale)
- 30+ new detection rules (50+ total)
- LICENSE file in project root
- CHANGELOG.md following Keep a Changelog format
- CODE_OF_CONDUCT.md (Contributor Covenant)

### Changed
- Improved terminal output with risk score visualization
- Enhanced SARIF output with CWE mappings

## [0.3.0] - 2025-01-25

### Added
- MCP server configuration scanning
- Slash commands scanning
- Custom rules scanning
- Docker configuration scanning
- Supply chain attack detection rules
- Secret leak detection (API keys, tokens, credentials)
- Malware signature database
- Watch mode (`--watch`) for real-time scanning
- Pre-commit hooks integration
- Snapshot testing infrastructure
- Cross-platform git hook support

### Changed
- Upgraded notify crate from v7 to v8

### Fixed
- Replaced `unwrap()` with `expect()` in all builtin rules for better error messages
- Cross-platform support for git hook permissions
- Resolved RUSTSEC-2024-0384 security advisory

## [0.2.0] - 2025-01-20

### Added
- Hooks scanning (`settings.json` support)
- SARIF output format for CI/CD integration
- 5 additional built-in security rules (17 total)
- Comprehensive security scanning features

## [0.1.0] - 2025-01-15

### Added
- Initial release
- Skills file scanning
- 12 built-in security rules
- Terminal output with colored severity levels
- JSON output format
- Basic CLI interface

[Unreleased]: https://github.com/ryo-ebata/cc-audit/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/ryo-ebata/cc-audit/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/ryo-ebata/cc-audit/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ryo-ebata/cc-audit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ryo-ebata/cc-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ryo-ebata/cc-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ryo-ebata/cc-audit/releases/tag/v0.1.0
