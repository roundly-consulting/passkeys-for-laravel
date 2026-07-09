# Passkeys for Laravel

A native **WebAuthn / FIDO2 passkey relying party** for Laravel — register and authenticate
passkeys with **no third-party crypto dependencies**. CBOR/COSE decoding, attestation and
assertion verification, and ES256/RS256 signature checks are all implemented in-package against
the [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) specification.

The package is deliberately **controller-less**: it ships actions, DTOs, a model, a challenge
store, native crypto primitives, and events, so your application wires its own HTTP endpoints
(stateless or session-based) on top.

## Requirements

- PHP 8.4+
- Laravel 12 or 13
- `ext-openssl`, `ext-json`
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
| `attestation` | — | `none` | Attestation conveyance preference (`none`/`indirect`/`direct`). |
| `user_verification` | — | `required` | UV requirement (`required`/`preferred`/`discouraged`). |
| `challenge.store` | `PASSKEYS_CHALLENGE_STORE` | default cache store | Cache store name for challenges. |
| `challenge.ttl` | `PASSKEYS_CHALLENGE_TTL` | `60` | Challenge lifetime in seconds. |
| `challenge.bytes` | — | `32` | Random challenge length in bytes. |
| `sign_count_policy` | — | `flag` | Counter-regression handling: `reject` throws, `flag` fires an event and proceeds. |
| `attestation_trust` | — | `ignore` | Trust policy for the attestation statement. |
| `reject_unknown_fmt` | — | `false` | Reject any attestation format other than `none`. |
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
$passkey = Passkeys::register(
    $user,
    RegistrationResponseData::fromArray($request->validated()),
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

```php
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\UserVerification;

$options = Passkeys::registrationOptions($user, new RegistrationOptionsOverrides(
    userVerification: UserVerification::Preferred,
    attestation: AttestationConveyance::Direct,
    timeoutMs: 30_000,
));
```

## Events

Listen to drive audit trails and anomaly handling:

- `RoundlyConsulting\Passkeys\Events\PasskeyRegistered`
- `RoundlyConsulting\Passkeys\Events\PasskeyAuthenticated`
- `RoundlyConsulting\Passkeys\Events\PasskeySignCountRegressed` — fired when a signature counter
  fails to advance under the `flag` policy.

## Security model

- **Single-use, TTL-bound challenges** stored in the cache (atomic get-and-forget → replay-safe).
- **Origin allow-list** and **RP ID hash** validation on every ceremony.
- **Constant-time challenge comparison** (`hash_equals`).
- **Signature verification** via `ext-openssl` (ES256 with DER↔raw handling, RS256); an
  `openssl_verify` error is treated as a failure, never a pass.
- **Sign-counter regression** policy (`reject` or `flag` + event) to surface cloned authenticators.
- **No user enumeration** — every authentication miss returns a uniform "credential not found".
- **Backup-eligibility consistency** (a backed-up credential must be backup-eligible).
- Attestation is recorded but not cryptographically verified under the default `none` policy.

## Testing

```bash
composer test
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md). Copyright © Roundly Consulting.
