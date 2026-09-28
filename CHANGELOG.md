# Changelog

All notable changes to `passkeys-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial public release.

### Added

- A native WebAuthn Level 2 / FIDO2 passkey relying party with ES256, RS256 and opt-in EdDSA
  credentials. Everything scoped to one account goes through `Passkeys::for($user)`:
  `registrationOptions()` / `register()`, `authenticationOptions()` / `authenticate()` (held to
  that account), `all()`, `find()`, `count()`, `exists()`, `rename()` and `revoke()`. The
  discoverable login stays flat: `Passkeys::authenticationOptions()` / `Passkeys::authenticate()`.
  `Passkeys::attestationFormats()` lists the verifiable attestation formats.
- The same API injectable as the `PasskeyService` contract (`PasskeyManager`), and each use case
  as an action — `GenerateRegistrationOptionsAction`, `VerifyRegistrationAction`,
  `GenerateAuthenticationOptionsAction`, `VerifyAuthenticationAction`, `RenamePasskeyAction`,
  `RevokePasskeyAction`.
- Controller-less by design — actions, DTOs, a `Passkey` model (swappable via `passkeys.model`)
  and a cache-backed challenge store, so you wire your own stateless or session-based endpoints.
- Usernameless (discoverable) sign-in, user-bound options, and second-factor checks with
  `AuthenticationExpectation::owner()` / `ownerType()`.
- Per-ceremony overrides for user verification, attestation, timeout, resident key and
  authenticator attachment.
- The `HasPasskeys` contract and `InteractsWithPasskeys` concern with user-model verbs
  (`passkeyRegistrationOptions()`, `registerPasskey()`, `passkeyAuthenticationOptions()`,
  `hasPasskeys()`, `passkeyCount()`) that delegate to `Passkeys::for($this)`, plus the `passkeyUserHandle()`
  Blueprint macro for the opaque, non-PII user handle.
- Credential management — `Passkeys::for($user)->rename()` / `revoke()` take a `Passkey` or its id
  and refuse another account's passkey with the uniform `CredentialNotFound`; plus the `ownedBy`
  scope and a display-safe `PasskeyResource`.
- Opt-in attestation verification with an `ignore` / `self` / `basic` trust ladder, `packed` and
  `apple` formats, configurable trust anchors (Apple and Google roots shipped), certificate
  validity checks and an AAGUID allow-list.
- Hardened ceremonies: single-use, ceremony- and user-bound challenges, origin and RP ID checks,
  sign-counter regression policy (`reject` or `flag`), and uniform errors that never enumerate
  users.
- `PasskeyRegistered`, `PasskeyAuthenticated`, `PasskeySignCountRegressed`, `PasskeyRevoked` and
  `PasskeyRenamed` events.
- `Passkeys::fake()` (`PasskeysFake`) with programmable outcomes and assertions — including
  `assertRenamed()` / `assertRevoked()` and their `assertNothing*()` twins, with calls through the
  model verbs recorded — and a `VirtualAuthenticator` for running real ceremonies in tests.

### Changed

- Account-scoped calls moved onto `Passkeys::for($user)`: `Passkeys::registrationOptions($user)`,
  `register($user, …)`, `authenticationOptions($user, …)`, `rename($passkey, …)` and
  `revoke($passkey)` are gone from the facade. The flat `authenticationOptions()` now takes only the
  overrides (`authenticationOptions(?$overrides)`).
- `PasskeyManager` is no longer bound as its own singleton — inject `PasskeyService`.
- The fake class `FakePasskeys` is now `PasskeysFake`.
