# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.1.1] - 2026-07-20

### Hardening
- Zeroize enroll-path secret material: confine the transient
  `chia_bls::SecretKey` scalars to the narrowest scope + drop immediately, route
  every owned byte buffer through `Zeroizing`, and narrow the zeroize claim to
  what is honestly delivered (foreign scalar wipe relied upon from upstream).
  Drops the unused direct `chia-bls` dependency. (#1327)

## [0.1.0] - 2026-07-20

### Features
- Initial dig-session facade (unlock/enroll/sign/inject) (#1)


