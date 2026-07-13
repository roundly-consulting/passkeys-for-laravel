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
- **Real attestation verification.** `attestation_trust` is a monotone ladder — `ignore` (default,
  unchanged behaviour: the format is recorded, the statement is never read) ⊂ `self` (the
  statement's maths must hold) ⊂ `basic` (maths + the chain must reach a configured trust anchor).
  `self` and `basic` no longer throw at boot.
  - `packed` attestation (WebAuthn §8.2): x5c batch attestation **and** self-attestation, with the
    §8.2.1 certificate requirements and the `id-fido-gen-ce-aaguid` binding.
  - One `AttestationGate` owns every trust ruling; per-format verifiers only prove maths.
  - Trust anchors per format (`attestation_anchors.paths`), anchored by equality **or** by
    completion (x5c usually omits the root). Google's published hardware-attestation roots ship in
    `resources/roots/` and are trusted unless `PASSKEYS_ATTESTATION_DEFAULT_ANCHORS=false`.
  - AAGUID allow-list (`aaguids.allowed`, `PASSKEYS_AAGUIDS_ALLOWED`).
  - New separately-catchable exceptions: `InvalidAttestation` (the maths failed),
    `AttestationUntrusted` (policy refused it), `AttestationRequired`,
    `UnsupportedAttestationFormat`.
  - Boot guard: `attestation_trust != ignore` with `attestation = none` fails at config-parse time
    instead of losing every registration.
  - New nullable `attestation_type` column (additive migration); existing rows stay null.
  - ⚠️ **Attestation certificates are held to their validity window** (leeway
    `attestation_clock_skew`, default 60 s, range 0–3600). An authenticator whose **batch
    certificate has lapsed** can no longer enrol under `self`/`basic`. This refuses real hardware,
    by design.
