<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\AttestationTrust;
use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;
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
    'attestation' => AttestationConveyance::None->value,
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

    // Attestation trust policy: 'ignore' records the format without verifying it.
    'attestation_trust' => AttestationTrust::Ignore->value,
    'reject_unknown_fmt' => false,

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
