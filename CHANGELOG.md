# Changelog

All notable changes to `passkeys-for-laravel` will be documented in this file.

## 1.0.0 - Unreleased

Initial release.

- Native WebAuthn / FIDO2 relying party — no third-party crypto dependencies.
- Registration (attestation) and authentication (assertion) ceremonies via a `Passkeys` facade,
  four actions, and typed DTOs.
- ES256 and RS256 signature verification (with optional Ed25519 when `ext-sodium` is present).
- In-package CBOR decoder, COSE key parser, ASN.1/SPKI assembly, and authenticator-data parser.
- Single-use, TTL-bound cache-backed challenge store.
- Passkey model, migration, factory, `HasPasskeys` contract, and `InteractsWithPasskeys` concern.
- Configurable sign-count regression policy, origin allow-list, and RP ID validation.
- `PasskeyRegistered`, `PasskeyAuthenticated`, and `PasskeySignCountRegressed` events.
- `Contracts\PasskeyService` interface behind the facade, plus a shipped testing double
  (`Passkeys::fake()` / `Testing\FakePasskeys`) with programmable outcomes, call recording, and
  runner-agnostic assertions — no authenticator crypto.
- Credential management: an optional friendly `name` at registration and `Passkeys::rename()` /
  `Passkeys::revoke()`.
- Safe serialisation: `Passkey` now hides `public_key` / `user_handle` / credential-id keys, plus a
  publishable `Http\Resources\PasskeyResource` for display-safe API output.
- User-model verbs on `InteractsWithPasskeys`: `passkeyRegistrationOptions()`, `registerPasskey()`,
  `passkeyAuthenticationOptions()`.
- Registration-options flexibility: `residentKey` / `authenticatorAttachment` overrides and a
  `resident_key` config default; documented Ed25519 opt-in.
- Widened `credential_id` storage (roaming security keys) with a sha-256-hashed unique index.
