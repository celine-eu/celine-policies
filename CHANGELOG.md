# CHANGELOG

<!-- version list -->

## v1.7.0 (2026-10-08)

### Bug Fixes

- Add additional scope for lookup
  ([`7fc92a4`](https://github.com/celine-eu/celine-policies/commit/7fc92a4d0f00316787bc3659447b83c529fe3cf1))

- Cleanup names
  ([`f956286`](https://github.com/celine-eu/celine-policies/commit/f9562865ce4824030d48ee047a7b341de58333d9))

- Correct gh workflow failure
  ([`ac7aee9`](https://github.com/celine-eu/celine-policies/commit/ac7aee91085e72d589f384058c74e8d86517cadf))

- Correct url encoding in requests, closes #7 expand users query size, closes #8
  ([`b00f232`](https://github.com/celine-eu/celine-policies/commit/b00f2325b2a86f290133971350e8661a92d3216f))

- Drop participants groups, cleanup clients.yaml
  ([`23feb66`](https://github.com/celine-eu/celine-policies/commit/23feb664fe71ac7e398901818344b72b46bb7d08))

- Fails on unmapped scopes, allow duplicated but identical scopes
  ([`58af0bb`](https://github.com/celine-eu/celine-policies/commit/58af0bbf4f11d4a8161a87cc2b6947bd25a661a4))

- Review clients.yaml provisioning
  ([`f84c484`](https://github.com/celine-eu/celine-policies/commit/f84c4842efd5441d00094141037ea2483fc9a115))

- Review init commands
  ([`3e49ed9`](https://github.com/celine-eu/celine-policies/commit/3e49ed9e953b8d5ace3dc57308b00f0e697882b6))

- Update sync command to check env=dev
  ([`b1d3369`](https://github.com/celine-eu/celine-policies/commit/b1d33697e5c5bb633837bce84b3d7c907bf29b02))

- **keycloak**: Bootstrap writes the admin cli secret only on request, as sync does
  ([`db2efc8`](https://github.com/celine-eu/celine-policies/commit/db2efc81a7fd51c90fb287e36b0e1a315b6967c9))

- **keycloak**: Mqtt scope only for broker clients, secrets file only on request
  ([`95da67b`](https://github.com/celine-eu/celine-policies/commit/95da67bde1e11dc4c33ccbe8137dcd17fd2201b2))

### Chores

- Add ENV=dev to local compose
  ([`02df115`](https://github.com/celine-eu/celine-policies/commit/02df115400f8d0293529b1298f90a653ffb22e3f))

- Add keycloack pgsql conn
  ([`16e30a6`](https://github.com/celine-eu/celine-policies/commit/16e30a628fbfcc73745d0e183f407eca826bd918))

- Drop the celine-sdk release TODOs now that 2.0.0 ships them
  ([`1882ceb`](https://github.com/celine-eu/celine-policies/commit/1882ceb3f4c73cafb70e3f37fe5be84f7f0ddb28))

- Ignore .ruff*
  ([`e5e7591`](https://github.com/celine-eu/celine-policies/commit/e5e7591c26afe4c3b36d0b73d476009967387bc1))

- Update harness
  ([`fb35651`](https://github.com/celine-eu/celine-policies/commit/fb3565160a799ada6b1fe4c0fdc6daa6e4ca997a))

- Upgrade celine-sdk to 2.0.0
  ([`f6920b8`](https://github.com/celine-eu/celine-policies/commit/f6920b89a1abfb5c7df628722594955769506f7b))

- Upgrade sdk
  ([`0eae186`](https://github.com/celine-eu/celine-policies/commit/0eae18665177246876117bf9e65412a7b4dc0b3c))

### Features

- Add --additive flag
  ([`7ef258d`](https://github.com/celine-eu/celine-policies/commit/7ef258d98959bfc556b4eac92a697d9dae76058d))

- Add additive/check options for merging clients
  ([`f14eaa5`](https://github.com/celine-eu/celine-policies/commit/f14eaa5c9ba26ff9d9e551870786e506f1725648))

- Add admin level persmissions, closes #2
  ([`79fb3e7`](https://github.com/celine-eu/celine-policies/commit/79fb3e7e3e3f7ee47f4c393685e72f90b79bf6ad))

- Add bootstrap, add ci parity test
  ([`606c12f`](https://github.com/celine-eu/celine-policies/commit/606c12fa171fcc8e50ecf0154c4e7c742e66c617))

- Add brute force handling, add MFA/webauthn support
  ([`22f578a`](https://github.com/celine-eu/celine-policies/commit/22f578a6e75eed33e049982a141b81700dd96ad8))

- Add email handling to provisioning
  ([`e229a0a`](https://github.com/celine-eu/celine-policies/commit/e229a0af8acb46ea6e884f390740622b40c53e2d))

- Add email verification after email change
  ([`9dd9966`](https://github.com/celine-eu/celine-policies/commit/9dd9966d6a163f3a9bbac59cca27df60b79bfe0c))

- Add LEGAL env to templates
  ([`d16e483`](https://github.com/celine-eu/celine-policies/commit/d16e4837f68ad5070f23089d86aa5842fb25998d))

- Add participants group container
  ([`bbc1f84`](https://github.com/celine-eu/celine-policies/commit/bbc1f843d070930693894c02ebf015892053af8c))

- Add provisioning service
  ([`6149502`](https://github.com/celine-eu/celine-policies/commit/61495026825e0e6823dd6a4549d654683ab87ec0))

- Add user invitation on provisioning, add mailpit for local tests, review policies cli with clear
  separation of activities (realm bootstrap, org setup, users sync)
  ([`eda24cb`](https://github.com/celine-eu/celine-policies/commit/eda24cb67e2e31264efd3e935ecdc6da4673d739))

- Allow ENV overrides on platform.yaml settings
  ([`dd6aa7d`](https://github.com/celine-eu/celine-policies/commit/dd6aa7d81a56b276a6c9c31dc9d8e97ab3ae7c51))

- Audit mqtt and provisioning refusals without claims, gate api docs, drop mqtt cors
  ([`421c5af`](https://github.com/celine-eu/celine-policies/commit/421c5af7bbfab21f7b83f982804e2150a2275d8c))

- Bind broker tokens to the mqtt scope (svc-mqtt audience)
  ([`cceb491`](https://github.com/celine-eu/celine-policies/commit/cceb491a7bd96201eff3e3962a2236190aee96d0))

- Declare hardcoded claim mappers on a client
  ([`f0f39c2`](https://github.com/celine-eu/celine-policies/commit/f0f39c26881b68d30ab9e1532b5105385977cf96))

- Divide setu phases per type
  ([`1e35f20`](https://github.com/celine-eu/celine-policies/commit/1e35f20d29baa139d16c58f85d9bf568d6b0dfc8))

- Drop google fonts dependency
  ([`ef642d9`](https://github.com/celine-eu/celine-policies/commit/ef642d9163ab62a42e3066a19b9431a253132e55))

- Extend scopes for onboarding, review sync
  ([`c3a9fb3`](https://github.com/celine-eu/celine-policies/commit/c3a9fb3c286ed38fbf7e744e87a68f1c90fac824))

- Force sync-users in dev only
  ([`3a1d6ea`](https://github.com/celine-eu/celine-policies/commit/3a1d6eaacc9f0b6e21213c79a053e06814e23678))

- Handle administration via participants
  ([`68e7334`](https://github.com/celine-eu/celine-policies/commit/68e7334b72b042fef6042806e0797993d6ea21d2))

- Review env mapping overrides
  ([`77cb62f`](https://github.com/celine-eu/celine-policies/commit/77cb62f8d3e058bd774069019ecdfe7fab4da1b6))

- Split the declaration, the dataspace is optional
  ([`e6079b5`](https://github.com/celine-eu/celine-policies/commit/e6079b587379b07f48a761f58def5ed4b00f0985))

- Test bootstrap, set safe defaults, import dev users
  ([`5aaf56f`](https://github.com/celine-eu/celine-policies/commit/5aaf56fb5189eaad59be215a9935939ec0d1685e))

- Upgrade keycloak 26.7.3
  ([`dc2bdb8`](https://github.com/celine-eu/celine-policies/commit/dc2bdb879a62aa2ce589b99da3e01bbac4428336))

- **keycloak**: Digital-twin.community.manage, the console's scope for a community's manager values
  ([`3eb5a2b`](https://github.com/celine-eu/celine-policies/commit/3eb5a2b84652a3983e224ef33d1865b466015745))

- **provisioning**: Move a released member's login out of the REC, re-enable it at the next join,
  refuse a second REC, and declare onboarding.members.release
  ([`60f5446`](https://github.com/celine-eu/celine-policies/commit/60f5446d57711563f2a8dc24c11c9619e4a2ea82))

- **provisioning**: Update a participant's names and email; declare per-field registry scopes
  ([`c4ad3e4`](https://github.com/celine-eu/celine-policies/commit/c4ad3e4c3f72a939b5f47786c3ddfbb08c229524))

### Testing

- Review output formatting
  ([`35d3e98`](https://github.com/celine-eu/celine-policies/commit/35d3e98e6f45fe8050b21510067ec7f8a2410983))


## v1.6.0 (2026-08-13)

### Bug Fixes

- Add ds permissions
  ([`d9d2430`](https://github.com/celine-eu/celine-policies/commit/d9d2430ccbf470c2938623c8852fa30367f0528b))

- Realign ds scopes
  ([`66941c8`](https://github.com/celine-eu/celine-policies/commit/66941c863897da924cca94d027704700774831a2))

### Chores

- Add external taskfile import
  ([`98b66d8`](https://github.com/celine-eu/celine-policies/commit/98b66d84a285b36f5104b02ff92a1fb2bbac0ebf))

- Add forecast service
  ([`1c2f6c1`](https://github.com/celine-eu/celine-policies/commit/1c2f6c1534def6845a5e04435d15a7b87c4adeae))

- Comment ds scopes
  ([`7008cc6`](https://github.com/celine-eu/celine-policies/commit/7008cc62a341ad83c6ab3083d90ec36677f9c0e7))

- Introduce ds clients
  ([`1036724`](https://github.com/celine-eu/celine-policies/commit/103672442339ca486ba62756c3fe068173c3c9c7))

- Update clietns
  ([`3db2114`](https://github.com/celine-eu/celine-policies/commit/3db2114aed5e1108aa2f8fe3dcc5f47f49c0b766))

- Upgrade celine-sdk to 1.13.0
  ([`d04cea1`](https://github.com/celine-eu/celine-policies/commit/d04cea16f1d731c88aa8adf9d11826198ae108bc))

### Features

- Add client and scopes for onboarding clients.yaml
  ([`347f76b`](https://github.com/celine-eu/celine-policies/commit/347f76b5419a8688e3a7d7d30af512a73434768a))

- Add ds clients
  ([`d1d4e40`](https://github.com/celine-eu/celine-policies/commit/d1d4e409d7ff0ecddb74a9aaef5a7f1e4cd9a370))

- Add ENV gate to block client id equal to secrets
  ([`fd052bb`](https://github.com/celine-eu/celine-policies/commit/fd052bb68a2e6d4a69d5be848729649c5b566c46))


## v1.5.1 (2026-05-08)

### Bug Fixes

- Grid rule setting
  ([`186cd29`](https://github.com/celine-eu/celine-policies/commit/186cd294617f409aa8aa2779fe64f605d4f12325))


## v1.5.0 (2026-05-07)

### Features

- Add scopes_prefix to svc-webapp for audience mapper derivation
  ([`312de81`](https://github.com/celine-eu/celine-policies/commit/312de81008fe40ce7b7fcd1073433d5878234f01))


## v1.4.0 (2026-05-07)

### Bug Fixes

- Add credentials on set org
  ([`12299ae`](https://github.com/celine-eu/celine-policies/commit/12299ae41b23b44b32113606ba3075267a7a71d6))

- Add groups, add org level groups
  ([`cd3a7ba`](https://github.com/celine-eu/celine-policies/commit/cd3a7baa655751f29c6d777a6a0dbf76ba833c0b))

### Chores

- Fix docker compose deps for dev setup
  ([`ce75dfa`](https://github.com/celine-eu/celine-policies/commit/ce75dfa9748bf563d2a5ff8198d45d5825dd4c3c))

- Remove pypi publishing
  ([`68972a3`](https://github.com/celine-eu/celine-policies/commit/68972a379d33de15716857af5099114d1f81ec0e))

- Update docs
  ([`782410d`](https://github.com/celine-eu/celine-policies/commit/782410d5bc1194804c4d07787ea62f819cbf9dbd))

- Update docs
  ([`26860af`](https://github.com/celine-eu/celine-policies/commit/26860afdafc4b81daa5a4d67fbe0f96a897e7078))

- Update keycloak theme title
  ([`3c410d7`](https://github.com/celine-eu/celine-policies/commit/3c410d7d387c1ca36a7669ed33db6ea5657bf52d))

- Upgrade celine-sdk to 1.11.0
  ([`f9c8457`](https://github.com/celine-eu/celine-policies/commit/f9c84570d78c87b204cb3bd823b0477d9ad498b3))

- Upgrade celine-sdk to 1.12.0
  ([`a9ab56b`](https://github.com/celine-eu/celine-policies/commit/a9ab56b2b169931ece0be7d833527073b30837db))

- Upgrade celine-sdk to 1.12.1
  ([`cc92acd`](https://github.com/celine-eu/celine-policies/commit/cc92acd444de1623cacf1b369d3488746464ccdd))

### Features

- Add set user organization command
  ([`1258afe`](https://github.com/celine-eu/celine-policies/commit/1258afe2c59b5d674d40049dd286e2d786c740d3))

- Added svc-webapp with nudging scope
  ([`c69101e`](https://github.com/celine-eu/celine-policies/commit/c69101e81dcbec521c76a3f8e1ac32f3f9fa5677))

- **keycloak**: Review theme
  ([`e20b662`](https://github.com/celine-eu/celine-policies/commit/e20b662911f01be258429a78afe24d424c65cc89))


## v1.3.0 (2026-04-16)

### Bug Fixes

- Corrected org mapper creation
  ([`8f0325d`](https://github.com/celine-eu/celine-policies/commit/8f0325df41a8fafd5b9962c1161fc29f01db380f))

- Review sync org
  ([`38dc21a`](https://github.com/celine-eu/celine-policies/commit/38dc21ac42645a528b03c481607fac4c64af1a3e))

### Chores

- Add rec registry export scope to pipelines
  ([`c9ca98c`](https://github.com/celine-eu/celine-policies/commit/c9ca98c342782b66de8a784cf2f4b9ea2a332be4))

- Update AGENTS
  ([`dc3a848`](https://github.com/celine-eu/celine-policies/commit/dc3a848f76393baa93103e5d83c39143cbce9e3f))

- Upgrade celine-sdk to 1.10.0
  ([`b1c5267`](https://github.com/celine-eu/celine-policies/commit/b1c5267ddfcbdba4d7b7cea8d209390216def3e7))

- Upgrade celine-sdk to 1.7.0
  ([`a996fdc`](https://github.com/celine-eu/celine-policies/commit/a996fdc102a2be5ae1c58022ada82cd5cf94c5e4))

- Upgrade celine-sdk to 1.8.0
  ([`1fde7c1`](https://github.com/celine-eu/celine-policies/commit/1fde7c12400d820780f00ed2c3f751878a1d6dae))

- Upgrade celine-sdk to 1.9.0
  ([`4290a48`](https://github.com/celine-eu/celine-policies/commit/4290a4899624b74fdd7607e06a5ac6563d9106e0))

- Upgrade keycloak version
  ([`3c3e1ef`](https://github.com/celine-eu/celine-policies/commit/3c3e1efa47a0f346e01a0767dd7b2ce87d27c232))

### Features

- Add flexibility export scope
  ([`3b20b11`](https://github.com/celine-eu/celine-policies/commit/3b20b1170bcee80077a1af8d1206f226e651e145))

- Add grid svc, upgrade keycloak
  ([`aa85331`](https://github.com/celine-eu/celine-policies/commit/aa85331d5f093dfa3c1aeeb89e36425b37c03e51))

- Add organization management
  ([`af66127`](https://github.com/celine-eu/celine-policies/commit/af66127379c29305caeb345ce2369e3ad2a82d06))

- Add organization support
  ([`7f321fa`](https://github.com/celine-eu/celine-policies/commit/7f321fa5d63f01398dddc54afb413704f14725cc))

- Add REC members to REC organization and assign group participant
  ([`a0cc710`](https://github.com/celine-eu/celine-policies/commit/a0cc7107bccb786bd9985c22446427bbace21d76))

- Ensure organization mapping on user import
  ([`96afe51`](https://github.com/celine-eu/celine-policies/commit/96afe51419d42f32c57d7f7101bcaf4a20fe17f3))


## v1.2.0 (2026-04-07)

### Bug Fixes

- Allow to mock users for local dev
  ([`38abdea`](https://github.com/celine-eu/celine-policies/commit/38abdea549d90b72948bbc86c3b1b611cf91b305))

- Correct signout
  ([`dc6ba9d`](https://github.com/celine-eu/celine-policies/commit/dc6ba9da8bceaa1b6bb7473401de31fc51a779be))

- Review template
  ([`60ccd62`](https://github.com/celine-eu/celine-policies/commit/60ccd624ce86591d005baf66650c5b752ab5f4c2))

- Update regorus
  ([`65d4f37`](https://github.com/celine-eu/celine-policies/commit/65d4f37b0aaf1c9515a892bc3a3dc05452f4da48))

### Chores

- Upgrade celine-sdk to 1.4.3
  ([`1d2043e`](https://github.com/celine-eu/celine-policies/commit/1d2043e1599a39fa560367033227e277ab7b5a30))

- Upgrade celine-sdk to 1.5.0
  ([`0d0cf7e`](https://github.com/celine-eu/celine-policies/commit/0d0cf7e63268b3014f50f004ab5a0dbb5ed0272a))

- Upgrade celine-sdk to 1.6.0
  ([`c42cced`](https://github.com/celine-eu/celine-policies/commit/c42cced75316c1adab1270329f5f0cca21e2df54))

### Features

- Add flexibility API
  ([`c5b1750`](https://github.com/celine-eu/celine-policies/commit/c5b17506779562faa49032988b46a03e12032f39))

- Add flexibilty commitment scope
  ([`71355a8`](https://github.com/celine-eu/celine-policies/commit/71355a8405afd87585157e71c144ba003b059234))


## v1.1.3 (2026-03-03)

### Bug Fixes

- Keycloak style
  ([`ae601a1`](https://github.com/celine-eu/celine-policies/commit/ae601a1cb122efd1eab71e03a07f5a9b6e7b24f2))


## v1.1.2 (2026-03-02)

### Bug Fixes

- Baiapp warning
  ([`bb3a43f`](https://github.com/celine-eu/celine-policies/commit/bb3a43fd1c66818e28b56d6d7a483900cc3a52a1))


## v1.1.1 (2026-03-02)

### Bug Fixes

- Force image build
  ([`2d6a8d8`](https://github.com/celine-eu/celine-policies/commit/2d6a8d8897992fbc8fa780c0b78d1193dc1fb2a5))


## v1.1.0 (2026-03-02)

### Bug Fixes

- Docker paths
  ([`2608759`](https://github.com/celine-eu/celine-policies/commit/26087590d0868cb5d411aa8e9f87bc4239ec7d5b))

### Features

- Add custom keycloak relase
  ([`144653c`](https://github.com/celine-eu/celine-policies/commit/144653c23335ec6bf464670aa92e00c0f16a6e01))

- Add sync users, set-password, fix broken init container
  ([`1b94979`](https://github.com/celine-eu/celine-policies/commit/1b94979a3020ef9685a22902c5299422153f5028))

- Fix compose, add sync users command
  ([`5cda21c`](https://github.com/celine-eu/celine-policies/commit/5cda21c6265fc3040ede96d44f72e3e08fd0d687))


## v1.0.2 (2026-03-01)

### Bug Fixes

- Update secret on sync, fix regex
  ([`011dcb2`](https://github.com/celine-eu/celine-policies/commit/011dcb29f8d2441a4c645ed7c4cdd90b1cbe0f86))


## v1.0.1 (2026-02-27)

### Bug Fixes

- Add skaffold, review docker
  ([`84a1d66`](https://github.com/celine-eu/celine-policies/commit/84a1d6675971bf72370636a4e9c3eb89384bc83e))


## v1.0.0 (2026-02-26)

- Initial Release
