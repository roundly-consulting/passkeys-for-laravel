# Changelog

All notable changes to `passkeys-for-laravel` are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- `Passkeys::authenticate()` and `Passkeys::for($user)->authenticate()` now refuse, with
  `CredentialNotFound`, a passkey whose owner was deleted or soft-deleted, or whose owner's stored
  user handle no longer matches the passkey's. An app that let soft-deleted accounts sign in with a
  passkey will notice.

### Fixed

- A passkey of a deleted or soft-deleted account no longer authenticates. It used to return a
  passkey whose `authenticatable` was `null`, so `Auth::login($passkey->authenticatable)` failed. A
  new account that reuses a deleted account's id no longer signs in with that account's passkeys,
  and the check mints no user handle.
- Spaces around the entries of `PASSKEYS_ORIGINS` and `PASSKEYS_AAGUIDS_ALLOWED`, or of the
  `passkeys.origins` / `passkeys.aaguids.allowed` arrays, are now trimmed. Before,
  `"https://example.com, https://www.example.com"` refused every ceremony from the second origin with
  `OriginMismatch`, and a spaced AAGUID refused that authenticator with `AttestationUntrusted`.
- Two registrations racing with the same credential id: the losing request now gets
  `CredentialAlreadyRegistered` instead of an `Illuminate\Database\UniqueConstraintViolationException`.

## 1.0.2 - 2026-10-04

### Fixed

- `InvalidConfiguration` messages for a mistyped `passkeys.*` setting now name the expected shape
  (for example "a list of strings") in the app's language instead of always in English.
- `InvalidAttestation` messages now say why a statement is malformed, or which WebAuthn certificate
  requirement failed, in the app's language. Raw certificate-parser errors no longer leak into the
  message; they stay available as the exception's previous exception.
- `MalformedCbor`, `InvalidCoseKey`, `InvalidAuthenticatorData` and `UnsupportedAlgorithm` no longer
  append the decoder's English error text to their translated message. Developers still get it: as
  the previous exception, and under `reason` in the log context Laravel records with the exception.

## 1.0.1 - 2026-10-04

### Changed

- Maintenance: `composer.json` `homepage` and `support.docs` now point to the documentation site.

### Fixed

- Slovak (`sk`) translations now ship alongside English for every language file.

## 1.0.0 - 2026-10-03

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
- Credential management — `Passkeys::for($user)->find()` / `rename()` / `revoke()` take a
  `Passkey` or its id (an `int`, or a route parameter's `string`) and refuse another account's
  passkey with the uniform `CredentialNotFound`; plus the `ownedBy`
  scope and a display-safe `PasskeyResource`.
- Opt-in attestation verification with an `ignore` / `self` / `basic` trust ladder, `packed` and
  `apple` formats, configurable trust anchors (Apple and Google roots shipped), RFC 5280 CA
  constraints (`CA:TRUE`, keyCertSign, pathLenConstraint) on every issuer in a chain, certificate
  validity checks and an AAGUID allow-list. Configuration is validated at boot, and its switches
  accept `1`/`0`/`on`/`off`/`yes`/`no` from `.env`.
- Hardened ceremonies: single-use, ceremony- and user-bound challenges, origin and RP ID checks,
  a forward-only, atomically advanced sign counter with a regression policy (`reject` or `flag`),
  the user handle required on usernameless assertions, WebAuthn L3 backup flags (eligibility
  fixed, state tracked), and uniform errors that never enumerate users.
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
