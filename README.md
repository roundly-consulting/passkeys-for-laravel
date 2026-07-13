<p align="center">
  <a href="https://roundly-consulting.com/open-source">
    <img src="art/hero.png" alt="Passkeys For Laravel — Roundly open source" width="100%">
  </a>
</p>

# Passkeys for Laravel

A native **WebAuthn / FIDO2 passkey relying party** for Laravel — register and authenticate
passkeys with **no third-party crypto dependencies**. The registration and authentication
ceremonies follow the [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) specification, and
ES256 / RS256 / EdDSA credentials are all supported.

The package is deliberately **controller-less**: it ships actions, DTOs, a model, a challenge
store, and events, so your application wires its own HTTP endpoints (stateless or session-based)
on top.

## Integrates with

- **[crypto-for-laravel](https://github.com/roundly-consulting/crypto-for-laravel)** — the
  cryptography this relying party runs on: CBOR/COSE decoding, COSE key parsing, ECDSA DER↔raw
  conversion, RSA/ECDSA/Ed25519 signature verification, base64url, SHA-256 and constant-time
  comparison. It is a hard dependency, installed automatically; there is nothing to configure.
  Passkeys keeps what is genuinely its own — the **ceremony**: challenge binding, origin and RP ID
  validation, user-presence/verification policy, sign-counter reconciliation, and attestation
  trust.
- **[enums-for-laravel](https://github.com/roundly-consulting/enums-for-laravel)** — the shared
  enum helpers (`values()`, `options()`, …) on this package's enums.

## Requirements

- PHP 8.4+
- Laravel 12 or 13
- `ext-json`
- `ext-sodium` (optional — only for Ed25519 / EdDSA verification)

## Installation

```bash
composer require roundly-consulting/passkeys-for-laravel
```

Publish and run the migration:

```bash
php artisan vendor:publish --tag="passkeys-migrations"
php artisan migrate
```

Optionally publish the config file:

```bash
php artisan vendor:publish --tag="passkeys-config"
```

Optionally publish the translation lines:

```bash
php artisan vendor:publish --tag="passkeys-translations"
```

## Configuration

`config/passkeys.php` documents every option. The security-critical values are `rp.id` and
`origins` — they **cannot be safely defaulted** and must be set for a ceremony to run.

| Key | Env | Default | Purpose |
|---|---|---|---|
| `rp.id` | `PASSKEYS_RP_ID` | host of `app.url` | Relying Party ID; a registrable-domain suffix of the origin (e.g. `example.com`). |
| `rp.name` | `PASSKEYS_RP_NAME` | `APP_NAME` | Human-readable RP name shown by the authenticator. |
| `origins` | `PASSKEYS_ORIGINS` | `[]` | Comma-separated allow-list of acceptable `clientData.origin` values. |
| `allow_cross_origin` | `PASSKEYS_ALLOW_CROSS_ORIGIN` | `false` | Whether a cross-origin (iframe) ceremony is accepted. |
| `algorithms` | — | `ES256`, `RS256` | COSE algorithms offered/accepted, in preference order. |
| `timeout_ms` | `PASSKEYS_TIMEOUT_MS` | `60000` | Ceremony timeout hint sent to the browser. |
| `attestation` | `PASSKEYS_ATTESTATION` | `none` | Attestation conveyance preference (`none`/`indirect`/`direct`). |
| `user_verification` | — | `required` | UV requirement (`required`/`preferred`/`discouraged`). |
| `resident_key` | `PASSKEYS_RESIDENT_KEY` | `required` | Discoverable-credential posture (`required`/`preferred`/`discouraged`); `required` keeps usernameless login. |
| `challenge.store` | `PASSKEYS_CHALLENGE_STORE` | default cache store | Cache store name for challenges. |
| `challenge.ttl` | `PASSKEYS_CHALLENGE_TTL` | `60` | Challenge lifetime in seconds. |
| `challenge.bytes` | — | `32` | Random challenge length in bytes. |
| `sign_count_policy` | — | `flag` | Counter-regression handling: `reject` throws, `flag` fires an event and proceeds. |
| `attestation_trust` | `PASSKEYS_ATTESTATION_TRUST` | `ignore` | Trust policy for the attestation statement: `ignore` / `self` / `basic` (see **Attestation**). |
| `reject_unknown_fmt` | `PASSKEYS_REJECT_UNKNOWN_FMT` | `false` | Under `ignore`, refuse a format we cannot verify — and a known format whose statement does not verify. |
| `attestation_anchors.defaults` | `PASSKEYS_ATTESTATION_DEFAULT_ANCHORS` | `true` | Trust the roots shipped in `resources/roots/` (Apple WebAuthn Root CA, Google hardware-attestation roots). |
| `attestation_anchors.paths` | — | `[]` | `format => [absolute PEM paths]` — your own trust anchors. |
| `attestation_clock_skew` | `PASSKEYS_ATTESTATION_CLOCK_SKEW` | `60` | Leeway (seconds, 0–3600) on both bounds of an attestation certificate's validity window. |
| `aaguids.allowed` | `PASSKEYS_AAGUIDS_ALLOWED` | `[]` | Comma-separated AAGUID allow-list; empty allows every authenticator model. |
| `user.handle_column` | `PASSKEYS_USER_HANDLE_COLUMN` | `passkey_user_handle` | Host column holding the opaque user handle. |
| `user.name_attribute` | — | `email` | Model attribute used as the account name. |
| `user.display_name_attribute` | — | `name` | Model attribute used as the display name. |

## Preparing your user model

Implement the `HasPasskeys` contract via the `InteractsWithPasskeys` concern, and add a nullable
column for the opaque, non-PII user handle (generated lazily on first registration):

```php
// database/migrations/xxxx_add_passkey_user_handle_to_users_table.php
$table->string('passkey_user_handle')->nullable();
```

```php
use Illuminate\Foundation\Auth\User as Authenticatable;
use RoundlyConsulting\Passkeys\Concerns\InteractsWithPasskeys;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;

final class User extends Authenticatable implements HasPasskeys
{
    use InteractsWithPasskeys;
}
```

The account name and display name default to the model's `email` and `name` attributes; override
the methods or repoint them via config.

The user handle is generated **lazily** and persisted on the first call to
`registrationOptions()`/`authenticationOptions($user)` — a small write on an otherwise read-shaped
call. The value is random, non-PII, and stable once set, so a rare double-write under concurrent
first-time requests is harmless (last write wins). If you prefer to avoid the lazy write entirely
(e.g. under heavy concurrency), generate the handle eagerly when the user is created:

```php
use Illuminate\Support\Str;

// e.g. in a User creating() observer
$user->passkey_user_handle ??= Str::random(43); // 32 random bytes, base64url
```

## Usage

The `Passkeys` facade is the single entry point. Each ceremony is two calls: generate options for
the browser, then verify the browser's response.

### Registration

```php
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;

// 1. Server -> client: creation options (also stores a single-use challenge).
$options = Passkeys::registrationOptions($user);
return response()->json($options); // feed publicKey to navigator.credentials.create()

// 2. Client -> server: verify the attestation response and persist the credential.
//    Pass an optional friendly name for a "your passkeys" screen.
$passkey = Passkeys::register(
    $user,
    RegistrationResponseData::fromArray($request->validated()),
    name: 'MacBook Touch ID',
);
```

### Authentication

```php
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;

// 1. Server -> client: request options (usernameless by default).
$options = Passkeys::authenticationOptions();      // or ::authenticationOptions($user)
return response()->json($options);                 // feed publicKey to navigator.credentials.get()

// 2. Client -> server: verify the assertion; the resolved credential's owner is reachable
//    via $passkey->authenticatable. The host then issues its own session or token.
$passkey = Passkeys::authenticate(
    AuthenticationResponseData::fromArray($request->validated()),
);
$user = $passkey->authenticatable;
```

The `ceremonyId` returned in the options travels back with the response so a stateless host can
correlate the challenge; a session-based host can echo it or store the challenge in the session.

### Per-call overrides

Tune a single ceremony without changing the global defaults. Beyond user verification,
attestation, and timeout you can opt into a **cross-platform** (roaming security-key) or a
**non-resident** credential:

```php
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\AuthenticatorAttachment;
use RoundlyConsulting\Passkeys\Enums\ResidentKey;
use RoundlyConsulting\Passkeys\Enums\UserVerification;

$options = Passkeys::registrationOptions($user, new RegistrationOptionsOverrides(
    userVerification: UserVerification::Preferred,
    attestation: AttestationConveyance::Direct,
    timeoutMs: 30_000,
    residentKey: ResidentKey::Discouraged,
    authenticatorAttachment: AuthenticatorAttachment::CrossPlatform,
));
```

The default posture stays `residentKey: required` (usernameless), and `authenticatorSelection`
serialises byte-identically when no override is given.

### Ed25519 (EdDSA) opt-in

Ed25519 (COSE `-8`) verification is fully implemented; it is simply not offered by default
because it needs `ext-sodium`. Once that extension is installed on every host that verifies these
credentials, add it to `config/passkeys.php`:

```php
use RoundlyConsulting\Crypto\Cose\CoseAlgorithm;

'algorithms' => [
    CoseAlgorithm::ES256->value,   // -7
    CoseAlgorithm::RS256->value,   // -257
    CoseAlgorithm::EdDSA->value,   // -8 (requires ext-sodium)
],
```

The COSE registry comes from `crypto-for-laravel`. This relying party accepts **only** ES256,
RS256 and EdDSA (`PasskeyConfig::SUPPORTED_ALGORITHMS`) — configuring any other identifier throws
`InvalidConfiguration` at boot rather than offering an algorithm the ceremony has not been vetted
against.

### Managing credentials

Rename or revoke a stored passkey through the facade — no need to touch the model directly. A
revoked credential is soft-deleted: it can no longer authenticate, and its credential id still
cannot be re-registered.

```php
Passkeys::rename($passkey, 'Work laptop');
Passkeys::revoke($passkey);     // soft-deletes the credential
```

### Listing credentials safely

The `Passkey` model hides `public_key`, `user_handle`, and the credential-id lookup keys from
array/JSON serialisation. Use the shipped `PasskeyResource` for an explicit, display-safe payload:

```php
use RoundlyConsulting\Passkeys\Http\Resources\PasskeyResource;

return PasskeyResource::collection($user->passkeys);
// [{ id, name, aaguid, transports, backup_eligible, backup_state, last_used_at, created_at }]
```

### User-model verbs

The `InteractsWithPasskeys` concern also exposes ceremony verbs so the user model is the subject:

```php
$options = $user->passkeyRegistrationOptions();               // ::registrationOptions($user)
$passkey = $user->registerPasskey($response, 'MacBook Touch ID');
$options = $user->passkeyAuthenticationOptions();             // scoped to this user's credentials
```

## Attestation

Attestation is how an authenticator proves **what it is**. It is off by default (the format is
recorded, the statement is never read), and turning it on is **two config lines**:

```dotenv
PASSKEYS_ATTESTATION=direct        # ask authenticators to attest
PASSKEYS_ATTESTATION_TRUST=basic   # and refuse anything unproven
```

Ceremony call sites do not change at all — attestation hardening is configuration, not code. What
changes is what you can see afterwards:

```php
$passkey->attestation_format;   // 'packed' | 'apple' | 'none'
$passkey->attestation_type;     // 'basic' | 'anonca' | 'self' | 'none' — the grade of proof established
```

### The trust ladder

| `attestation_trust` | What it accepts |
|---|---|
| `ignore` (default) | Everything. The format is recorded; **no statement is ever read**. |
| `self` | The statement's **maths must hold** — signature, chain linkage, certificate validity dates. Anchoring is waived, so self-attestation and an un-anchored batch certificate both pass. |
| `basic` | The maths must hold **and** the certificate chain must reach a configured **trust anchor**. Self-attestation is refused. |

Supported formats:

| `fmt` | Who sends it | Attestation type established |
|---|---|---|
| `none` | Everything, unless you ask for `direct` | `none` |
| `packed` | CTAP2 security keys and most platform authenticators | `basic` (x5c) or `self` (no x5c) |
| `apple` | Apple platform authenticators (Touch ID / Face ID) | `anonca` |

An authenticator presenting anything else under `self`/`basic` is refused by name
(`UnsupportedAttestationFormat`).

**Apple attests anonymously.** Its statement carries no signature over the ceremony at all: the
credential certificate instead carries a nonce equal to `SHA-256(authenticatorData ‖
clientDataHash)`, and certifies the credential's own public key. Both are verified, which is what
makes a statement from another ceremony unusable here. The grade it establishes is `anonca` —
"a genuine Apple authenticator", never a device identity, which is exactly what Apple intends.

### Trust anchors

A chain is anchored when its last certificate **is** an anchor, or is **signed by** one (x5c
commonly omits the root). Security keys attest under their vendor's own root, so supply it:

```php
'attestation_anchors' => [
    'paths' => ['packed' => [storage_path('webauthn/vendor-fido-ca.pem')]],
],
```

The package ships **Apple's published WebAuthn Root CA** and **Google's published
hardware-attestation roots** in `resources/roots/` (trusted unless
`PASSKEYS_ATTESTATION_DEFAULT_ANCHORS=false`); every fingerprint is pinned in the test suite. So
**Apple devices verify under `basic` with no anchor setup at all** — Apple omits the root from its
`x5c`, and the shipped anchor completes the chain. Every rejection names the format, the offending
value and the config key that fixes it:

> The `'packed'` attestation chain's root (`"CN=Some Vendor CA, O=Vendor"`, sha256 `9f3ae1c2…`) is
> not among the configured trust anchors. Add its PEM to
> `passkeys.attestation_anchors.paths.packed`.

### Certificate validity dates

Attestation certificates are held to their validity window (both bounds, with
`attestation_clock_skew` seconds of leeway — default `60`, range `0–3600`; anything else fails at
boot with `InvalidConfiguration`).

> ⚠️ **This refuses real hardware.** An authenticator whose batch certificate has **lapsed** can no
> longer enrol under `self`/`basic`. That is deliberate — an expired chain is not something a
> relying party should silently bless — but it is a real-world consequence to plan for.

### AAGUID allow-list

```dotenv
PASSKEYS_AAGUIDS_ALLOWED=d8522d9f-575b-4866-88a9-ba99fa02f35b
```

Empty (the default) allows every authenticator model. The AAGUID is only **proven** under `basic`
(the batch certificate binds it); under the lower tiers the authenticator merely asserts it — the
list is still enforced when configured.

### Catching failures

Two separately catchable outcomes, so forgeries and policy refusals are never confused:

- `InvalidAttestation` — the **maths** failed (malformed statement, bad signature, algorithm
  mismatch, AAGUID mismatch, a certificate requirement).
- `AttestationUntrusted` — the statement is sound and **policy refused it** (unanchored root, no
  anchors configured, self-attestation under `basic`, expired certificate, AAGUID not allowed).
- `AttestationRequired` — the tier demands a statement and the authenticator sent `none`.

Both extend `PasskeyException`. Setting `attestation_trust` to anything but `ignore` while
`attestation` is `none` fails at **boot**, not at the first lost registration.

### Testing your policy

Point the anchors at a throwaway chain and any `packed` happy path becomes a three-line test:

```php
file_put_contents($path, $chain->root()->pem());
config()->set('passkeys.attestation_anchors', ['defaults' => false, 'paths' => ['packed' => [$path]]]);
```

## Events

Listen to drive audit trails and anomaly handling:

- `RoundlyConsulting\Passkeys\Events\PasskeyRegistered`
- `RoundlyConsulting\Passkeys\Events\PasskeyAuthenticated`
- `RoundlyConsulting\Passkeys\Events\PasskeySignCountRegressed` — fired when a signature counter
  fails to advance under the `flag` policy.

## Security model

- **Single-use, TTL-bound challenges** stored in the cache (atomic get-and-forget → replay-safe).
- **Ceremony-bound challenges** — each challenge records whether it was minted for registration or
  authentication and is rejected if presented to the wrong verifier.
- **User-bound registration challenges** — the challenge records the target user handle and the
  registration verifier rejects a response for a different user (defense-in-depth for
  admin-on-behalf flows).
- **Origin allow-list** and **RP ID hash** validation on every ceremony.
- **Constant-time challenge comparison** (crypto's `ConstantTime::equals`).
- **Signature verification** through `crypto-for-laravel` (ES256 with DER↔raw handling, RS256,
  Ed25519); a verification error is treated as a failure, never a pass.
- **No algorithm confusion** — the verification algorithm is read from the **stored credential's**
  own COSE key, never from the assertion, and the configured allow-list is enforced at
  registration.
- **Sign-counter regression** policy (`reject` or `flag` + event) to surface cloned authenticators.
- **No user enumeration** — every authentication miss returns a uniform "credential not found".
- **Backup-eligibility consistency** (a backed-up credential must be backup-eligible).
- **Attestation trust** — a monotone ladder (`ignore` ⊂ `self` ⊂ `basic`) with `ignore` as the
  default: the format is recorded and the statement is never read. `self` verifies the statement's
  maths; `basic` additionally requires the certificate chain to reach a configured trust anchor.
  Format verifiers only prove maths; every trust ruling is made in one place (`AttestationGate`).
  See **Attestation** below.
- **Roaming-key credential ids** are stored in full (up to ~1364 base64url chars); the unique
  index is keyed on a sha-256 hash of the credential id so it stays within every database's
  key-length limit.

## Testing

`Passkeys::fake()` swaps the relying party for a programmable, **no-crypto** double so a host can
assert its enrolment/login controllers without reproducing authenticator crypto. It performs no
CBOR/COSE decode, signature verification, or challenge check, and is bound only for the test.

```php
use RoundlyConsulting\Passkeys\Facades\Passkeys;

$fake = Passkeys::fake();

// drive your endpoints with any payload shape…
$this->postJson('/passkeys', ['id' => 'x', 'rawId' => 'x', 'response' => []])->assertCreated();

$fake->assertRegisteredFor($user);

// programmable outcomes:
Passkeys::fake()->rejectAuthentication();          // authenticate() throws CredentialNotFound
Passkeys::fake()->authenticatesAs($passkey);       // authenticate() returns this exact credential
Passkeys::fake()->failRegistrationWith($exception);
```

Assertions (`assertRegistered`, `assertRegisteredFor`, `assertNothingRegistered`,
`assertAuthenticated`, `assertAuthenticatedFor`, `assertAuthenticationFailed`,
`assertRegistrationCount`, `assertAuthenticationCount`) throw a package exception, so they work
under any runner.

Run the package's own suite with:

```bash
composer test
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md). Copyright © Roundly Consulting.
