<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\AttestationTrust;
use RoundlyConsulting\Passkeys\Enums\ResidentKey;
use RoundlyConsulting\Passkeys\Enums\SignCountPolicy;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Models\Passkey;

return [

    /*
    |--------------------------------------------------------------------------
    | Relying Party
    |--------------------------------------------------------------------------
    |
    | The rp.id must be a registrable-domain suffix of the ceremony origin
    | (e.g. "example.com"). When null, it is derived from the host of app.url.
    |
    */
    'rp' => [
        'id' => env('PASSKEYS_RP_ID'),
        'name' => env('PASSKEYS_RP_NAME', env('APP_NAME', 'Laravel')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Allowed origins
    |--------------------------------------------------------------------------
    |
    | The exact clientData.origin values a ceremony may present, as a
    | comma-separated list (e.g. "https://example.com,https://www.example.com").
    | At least one origin must be configured before a ceremony can run.
    |
    */
    'origins' => array_values(array_filter(
        explode(',', (string) env('PASSKEYS_ORIGINS', '')),
    )),

    // Whether a cross-origin (iframe) ceremony is acceptable. Default: reject.
    'allow_cross_origin' => (bool) env('PASSKEYS_ALLOW_CROSS_ORIGIN', false),

    // COSE algorithms offered/accepted, in preference order. Ed25519 (EdDSA,
    // COSE -8) is fully supported — opt in by uncommenting the line below once
    // ext-sodium is installed on every host that verifies these credentials.
    'algorithms' => [
        CoseAlgorithm::ES256->value,   // -7
        CoseAlgorithm::RS256->value,   // -257
        // CoseAlgorithm::EdDSA->value, // -8 (requires ext-sodium)
    ],

    'timeout_ms' => (int) env('PASSKEYS_TIMEOUT_MS', 60_000),

    // The attestation-conveyance preference sent in creation options. Anything
    // stricter than 'ignore' below needs 'direct' here, or authenticators are
    // told not to attest at all.
    'attestation' => env('PASSKEYS_ATTESTATION', AttestationConveyance::None->value),

    'user_verification' => UserVerification::Required->value,

    /*
    |--------------------------------------------------------------------------
    | Resident key (discoverable credential) requirement
    |--------------------------------------------------------------------------
    |
    | The default global posture for new credentials. 'required' keeps the
    | usernameless / discoverable-login experience; 'preferred'/'discouraged'
    | allow non-resident credentials. A per-call RegistrationOptionsOverrides
    | (with residentKey / authenticatorAttachment) overrides this per ceremony.
    |
    */
    'resident_key' => env('PASSKEYS_RESIDENT_KEY', ResidentKey::Required->value),

    /*
    |--------------------------------------------------------------------------
    | Challenge storage
    |--------------------------------------------------------------------------
    |
    | Challenges are single-use and TTL-bound in the cache. The TTL should match
    | the ceremony timeout. `store` is a cache store name (null = default store).
    |
    */
    'challenge' => [
        'store' => env('PASSKEYS_CHALLENGE_STORE'),
        'ttl' => (int) env('PASSKEYS_CHALLENGE_TTL', 60),
        'bytes' => 32,
    ],

    // Sign-counter regression handling: 'reject' throws, 'flag' fires an event.
    'sign_count_policy' => SignCountPolicy::Flag->value,

    /*
    |--------------------------------------------------------------------------
    | Attestation trust policy
    |--------------------------------------------------------------------------
    |
    | The ladder is monotone — ignore ⊂ self ⊂ basic:
    |
    |   'ignore' (default) — record the format, never read the statement. A host
    |                        that never touches this sees no verification at all.
    |   'self'             — the statement's maths must hold (signature, chain
    |                        linkage, certificate validity dates); anchoring is
    |                        waived, so self-attestation is accepted.
    |   'basic'            — the maths must hold AND the certificate chain must
    |                        reach a configured trust anchor. Self-attestation is
    |                        refused.
    |
    | Turning real attestation on is two lines: PASSKEYS_ATTESTATION=direct and
    | PASSKEYS_ATTESTATION_TRUST=basic.
    |
    */
    'attestation_trust' => env('PASSKEYS_ATTESTATION_TRUST', AttestationTrust::Ignore->value),

    // Under 'ignore', also refuse a format this package has no verifier for, and
    // refuse a known format whose statement does not verify. Trust anchors are
    // still not consulted. Default: accept everything, verify nothing.
    'reject_unknown_fmt' => (bool) env('PASSKEYS_REJECT_UNKNOWN_FMT', false),

    /*
    |--------------------------------------------------------------------------
    | Attestation trust anchors
    |--------------------------------------------------------------------------
    |
    | Which roots an attestation chain may terminate at, per format. A chain is
    | anchored when its last certificate IS an anchor, or is signed by one (x5c
    | usually omits the root).
    |
    | 'defaults' trusts the roots shipped in this package's resources/roots —
    | Apple's published WebAuthn Root CA (so Apple devices verify with no further
    | setup) and Google's published hardware-attestation roots. Set it to false to
    | trust ONLY the paths below.
    |
    | 'paths' maps a format to absolute PEM (or PEM-bundle) paths on the host's
    | filesystem. Security keys attest under their vendor's own root, so 'packed'
    | ships no default: supply your vendor's PEM.
    |
    */
    'attestation_anchors' => [
        'defaults' => (bool) env('PASSKEYS_ATTESTATION_DEFAULT_ANCHORS', true),

        'paths' => [
            // 'packed' => [storage_path('webauthn/vendor-fido-ca.pem')],
        ],
    ],

    // Clock-skew leeway (seconds) applied to BOTH bounds of an attestation
    // certificate's validity window. 0–3600; anything else fails at boot.
    // Note: an authenticator whose batch certificate has lapsed can no longer
    // enrol under 'self'/'basic'. That is deliberate.
    'attestation_clock_skew' => (int) env('PASSKEYS_ATTESTATION_CLOCK_SKEW', 60),

    /*
    |--------------------------------------------------------------------------
    | AAGUID allow-list
    |--------------------------------------------------------------------------
    |
    | Lowercase, formatted UUIDs, comma-separated. Empty (the default) allows any
    | authenticator model. An AAGUID is only PROVEN under 'basic' — under the
    | lower tiers the authenticator asserts it, so the list is advisory there,
    | and it is still enforced when configured.
    |
    */
    'aaguids' => [
        'allowed' => array_values(array_filter(
            explode(',', (string) env('PASSKEYS_AAGUIDS_ALLOWED', '')),
        )),
    ],

    /*
    |--------------------------------------------------------------------------
    | User model wiring
    |--------------------------------------------------------------------------
    |
    | The host owns the opaque, non-PII user handle column. The name / display
    | name shown in the authenticator UI default to these model attributes.
    |
    */
    'user' => [
        'handle_column' => env('PASSKEYS_USER_HANDLE_COLUMN', 'passkey_user_handle'),
        'handle_bytes' => 32,
        'name_attribute' => 'email',
        'display_name_attribute' => 'name',
    ],

    // Eloquent wiring.
    'model' => Passkey::class,
    'table' => 'passkeys',

];
