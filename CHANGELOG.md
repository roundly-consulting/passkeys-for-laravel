# Changelog

All notable changes to `passkeys-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial public release.

### Added

- A native WebAuthn Level 2 / FIDO2 passkey relying party: registration and authentication
  ceremonies through the `Passkeys` facade (`registrationOptions()` / `register()`,
  `authenticationOptions()` / `authenticate()`), with ES256, RS256 and opt-in EdDSA credentials.
- Controller-less by design — actions, DTOs, a `Passkey` model (swappable via `passkeys.model`)
  and a cache-backed challenge store, so you wire your own stateless or session-based endpoints.
- Usernameless (discoverable) sign-in, user-bound options, and second-factor checks with
  `AuthenticationExpectation::owner()` / `ownerType()`.
- Per-ceremony overrides for user verification, attestation, timeout, resident key and
  authenticator attachment.
- The `HasPasskeys` contract and `InteractsWithPasskeys` concern with user-model verbs
  (`registerPasskey()`, `hasPasskeys()`, `passkeyCount()`), plus the `passkeyUserHandle()`
  Blueprint macro for the opaque, non-PII user handle.
- Credential management — `Passkeys::rename()`, `Passkeys::revoke()`, the `ownedBy` scope and a
  display-safe `PasskeyResource`.
- Opt-in attestation verification with an `ignore` / `self` / `basic` trust ladder, `packed` and
  `apple` formats, configurable trust anchors (Apple and Google roots shipped), certificate
  validity checks and an AAGUID allow-list.
- Hardened ceremonies: single-use, ceremony- and user-bound challenges, origin and RP ID checks,
  sign-counter regression policy (`reject` or `flag`), and uniform errors that never enumerate
  users.
- `PasskeyRegistered`, `PasskeyAuthenticated`, `PasskeySignCountRegressed`, `PasskeyRevoked` and
  `PasskeyRenamed` events.
- `Passkeys::fake()` with assertions and programmable outcomes, and a `VirtualAuthenticator` for
  running real ceremonies in tests.
