<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\CoseAlgorithm;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\AttestationTrust;
use RoundlyConsulting\Passkeys\Enums\ResidentKey;
use RoundlyConsulting\Passkeys\Enums\SignCountPolicy;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Exceptions\InvalidConfiguration;

it('reads a fully-specified config into typed values', function (): void {
    $config = PasskeyConfig::fromArray([
        'rp' => ['id' => 'example.com', 'name' => 'Example'],
        'origins' => ['https://example.com', 'https://www.example.com'],
        'allow_cross_origin' => true,
        'algorithms' => [-7, '-257'],
        'timeout_ms' => 30_000,
        'attestation' => 'direct',
        'user_verification' => 'preferred',
        'challenge' => ['store' => 'redis', 'ttl' => 120, 'bytes' => 64],
        'sign_count_policy' => 'reject',
        'attestation_trust' => 'ignore',
        'reject_unknown_fmt' => true,
        'resident_key' => 'discouraged',
        'user' => ['handle_column' => 'handle', 'handle_bytes' => 48, 'name_attribute' => 'username', 'display_name_attribute' => 'full_name'],
    ]);

    expect($config->rpId)->toBe('example.com')
        ->and($config->rpName)->toBe('Example')
        ->and($config->origins)->toBe(['https://example.com', 'https://www.example.com'])
        ->and($config->allowCrossOrigin)->toBeTrue()
        ->and($config->algorithms)->toBe([-7, -257])
        ->and($config->timeoutMs)->toBe(30_000)
        ->and($config->attestation)->toBe(AttestationConveyance::Direct)
        ->and($config->userVerification)->toBe(UserVerification::Preferred)
        ->and($config->challengeStore)->toBe('redis')
        ->and($config->challengeTtl)->toBe(120)
        ->and($config->challengeBytes)->toBe(64)
        ->and($config->signCountPolicy)->toBe(SignCountPolicy::Reject)
        ->and($config->attestationTrust)->toBe(AttestationTrust::Ignore)
        ->and($config->residentKey)->toBe(ResidentKey::Discouraged)
        ->and($config->rejectUnknownFmt)->toBeTrue()
        ->and($config->userHandleColumn)->toBe('handle')
        ->and($config->userHandleBytes)->toBe(48)
        ->and($config->userNameAttribute)->toBe('username')
        ->and($config->userDisplayNameAttribute)->toBe('full_name');
});

it('applies sensible defaults for an empty config', function (): void {
    $config = PasskeyConfig::fromArray([]);

    expect($config->rpId)->toBeNull()
        ->and($config->rpName)->toBe('Laravel')
        ->and($config->origins)->toBe([])
        ->and($config->allowCrossOrigin)->toBeFalse()
        ->and($config->algorithms)->toBe([CoseAlgorithm::ES256->value, CoseAlgorithm::RS256->value])
        ->and($config->timeoutMs)->toBe(60_000)
        ->and($config->attestation)->toBe(AttestationConveyance::None)
        ->and($config->userVerification)->toBe(UserVerification::Required)
        ->and($config->challengeStore)->toBeNull()
        ->and($config->signCountPolicy)->toBe(SignCountPolicy::Flag)
        ->and($config->residentKey)->toBe(ResidentKey::Required)
        ->and($config->userHandleColumn)->toBe('passkey_user_handle');
});

it('derives the rp id from the app url host when not set', function (): void {
    expect(PasskeyConfig::fromArray(['rp' => ['id' => '']], 'https://sub.example.com/path')->rpId)
        ->toBe('sub.example.com');
});

it('leaves the rp id null when neither config nor a usable url is given', function (): void {
    expect(PasskeyConfig::fromArray([], 'not a url with host')->rpId)->toBeNull();
    expect(PasskeyConfig::fromArray([], '')->rpId)->toBeNull();
});

it('requires an rp id before a ceremony runs', function (): void {
    PasskeyConfig::fromArray([])->requireRpId();
})->throws(InvalidConfiguration::class);

it('returns the rp id when present', function (): void {
    expect(PasskeyConfig::fromArray(['rp' => ['id' => 'example.com']])->requireRpId())->toBe('example.com');
});

it('requires at least one origin before a ceremony runs', function (): void {
    PasskeyConfig::fromArray([])->requireOrigins();
})->throws(InvalidConfiguration::class);

it('returns the configured origins', function (): void {
    expect(PasskeyConfig::fromArray(['origins' => ['https://example.com']])->requireOrigins())
        ->toBe(['https://example.com']);
});

it('defaults the attestation trust to ignore', function (): void {
    expect(PasskeyConfig::fromArray([])->attestationTrust)->toBe(AttestationTrust::Ignore);
});

it('accepts every trust level now that the ladder is real', function (string $trust): void {
    $config = PasskeyConfig::fromArray([
        'attestation' => 'direct',
        'attestation_trust' => $trust,
    ]);

    expect($config->attestationTrust->value)->toBe($trust);
})->with(['ignore', 'self', 'basic']);

it('refuses to demand attestation while telling authenticators not to send any', function (string $trust): void {
    PasskeyConfig::fromArray([
        'attestation' => 'none',
        'attestation_trust' => $trust,
    ]);
})->throws(InvalidConfiguration::class, 'PASSKEYS_ATTESTATION=direct')->with(['self', 'basic']);

it('leaves the default posture alone: ignore with none conveyance is fine', function (): void {
    $config = PasskeyConfig::fromArray(['attestation' => 'none', 'attestation_trust' => 'ignore']);

    expect($config->attestationTrust)->toBe(AttestationTrust::Ignore);
});

it('defaults the attestation clock skew to a minute', function (): void {
    expect(PasskeyConfig::fromArray([])->attestationClockSkew)->toBe(60)
        ->and(PasskeyConfig::MAX_ATTESTATION_CLOCK_SKEW)->toBe(3600);
});

it('accepts a clock skew at either bound', function (int $seconds): void {
    expect(PasskeyConfig::fromArray(['attestation_clock_skew' => $seconds])->attestationClockSkew)->toBe($seconds);
})->with([0, 3600]);

it('fails loudly on a clock skew outside its range', function (mixed $value): void {
    PasskeyConfig::fromArray(['attestation_clock_skew' => $value]);
})->throws(InvalidConfiguration::class, 'attestation_clock_skew')->with([-1, 3601, 'soon', true]);

it('trusts the shipped anchors by default and can be told not to', function (): void {
    expect(PasskeyConfig::fromArray([])->attestationAnchorDefaults)->toBeTrue()
        ->and(PasskeyConfig::fromArray(['attestation_anchors' => ['defaults' => false]])->attestationAnchorDefaults)->toBeFalse();
});

it('normalises the aaguid allow-list to lowercase', function (): void {
    $config = PasskeyConfig::fromArray([
        'aaguids' => ['allowed' => ['ABCDEF01-1111-1111-1111-111111111111']],
    ]);

    expect($config->allowedAaguids)->toBe(['abcdef01-1111-1111-1111-111111111111'])
        ->and(PasskeyConfig::fromArray([])->allowedAaguids)->toBe([]);
});

it('refuses a mistyped allow-list instead of reading it as allow-anything (strict config)', function (string $list, mixed $value): void {
    $config = $list === 'origins' ? ['origins' => $value] : ['aaguids' => ['allowed' => $value]];

    expect(fn (): PasskeyConfig => PasskeyConfig::fromArray($config))
        ->toThrow(InvalidConfiguration::class, "passkeys.{$list}");
})->with([
    'aaguids not a list' => ['aaguids.allowed', 'nope'],
    'aaguids non-string entry' => ['aaguids.allowed', ['ABCDEF01-1111-1111-1111-111111111111', 42]],
    'aaguids blank entry' => ['aaguids.allowed', ['']],
    'origins not a list' => ['origins', 'https://example.com'],
    'origins non-string entry' => ['origins', ['https://example.com', 5]],
    'origins blank entry' => ['origins', ['https://example.com', '']],
]);

it('refuses a junk algorithm list instead of offering the defaults (strict config)', function (mixed $algorithms): void {
    PasskeyConfig::fromArray(['algorithms' => $algorithms]);
})->with([
    'word entry' => [[-7, 'x']],
    'float string entry' => [['-7.0']],
    'empty list' => [[]],
    'not a list' => ['-7'],
])->throws(InvalidConfiguration::class, 'passkeys.algorithms');

it('refuses a typo in an enum setting instead of a ValueError or the default (strict config)', function (string $key, string $typo): void {
    expect(fn (): PasskeyConfig => PasskeyConfig::fromArray([$key => $typo]))
        ->toThrow(InvalidConfiguration::class, "passkeys.{$key}");
})->with([
    'attestation' => ['attestation', 'Direct'],
    'attestation_trust' => ['attestation_trust', 'basik'],
    'user_verification' => ['user_verification', 'required '],
    'resident_key' => ['resident_key', 'yes'],
    'sign_count_policy' => ['sign_count_policy', 'warn'],
]);

it('refuses a non-string enum setting instead of the default (strict config)', function (): void {
    PasskeyConfig::fromArray(['user_verification' => true]);
})->throws(InvalidConfiguration::class, 'passkeys.user_verification');

it('refuses a junk or out-of-range integer instead of reading it as 0 (strict config)', function (array $config, string $key): void {
    expect(fn (): PasskeyConfig => PasskeyConfig::fromArray($config))
        ->toThrow(InvalidConfiguration::class, "passkeys.{$key}");
})->with([
    'timeout word' => [['timeout_ms' => 'five'], 'timeout_ms'],
    'timeout zero' => [['timeout_ms' => 0], 'timeout_ms'],
    'challenge ttl float string' => [['challenge' => ['ttl' => '1.5']], 'challenge.ttl'],
    'challenge ttl zero' => [['challenge' => ['ttl' => '0']], 'challenge.ttl'],
    'challenge bytes under 16' => [['challenge' => ['bytes' => 8]], 'challenge.bytes'],
    'handle bytes over 64' => [['user' => ['handle_bytes' => 65]], 'user.handle_bytes'],
    'handle bytes under 16' => [['user' => ['handle_bytes' => 8]], 'user.handle_bytes'],
    'clock skew exponent' => [['attestation_clock_skew' => '1e3'], 'attestation_clock_skew'],
    'clock skew float string' => [['attestation_clock_skew' => '1.5'], 'attestation_clock_skew'],
]);

it('reads canonical integer strings from env (strict config)', function (): void {
    $config = PasskeyConfig::fromArray([
        'timeout_ms' => '30000',
        'challenge' => ['ttl' => ' 90 '],
        'attestation_clock_skew' => '0',
    ]);

    expect($config->timeoutMs)->toBe(30_000)
        ->and($config->challengeTtl)->toBe(90)
        ->and($config->attestationClockSkew)->toBe(0);
});

it('refuses a non-string string setting instead of the default (strict config)', function (array $config, string $key): void {
    expect(fn (): PasskeyConfig => PasskeyConfig::fromArray($config))
        ->toThrow(InvalidConfiguration::class, "passkeys.{$key}");
})->with([
    'rp id not a string' => [['rp' => ['id' => 42]], 'rp.id'],
    'rp name not a string' => [['rp' => ['name' => ['Acme']]], 'rp.name'],
    'challenge store not a string' => [['challenge' => ['store' => ['redis']]], 'challenge.store'],
    'handle column not a string' => [['user' => ['handle_column' => 7]], 'user.handle_column'],
    'name attribute not a string' => [['user' => ['name_attribute' => false]], 'user.name_attribute'],
]);

it('reads a blank setting as not set, so its default applies (strict config)', function (string $blank): void {
    $config = PasskeyConfig::fromArray([
        'rp' => ['name' => $blank],
        'origins' => $blank,
        'algorithms' => $blank,
        'allow_cross_origin' => $blank,
        'timeout_ms' => $blank,
        'attestation' => $blank,
        'user_verification' => $blank,
        'resident_key' => $blank,
        'challenge' => ['store' => $blank, 'ttl' => $blank, 'bytes' => $blank],
        'sign_count_policy' => $blank,
        'attestation_trust' => $blank,
        'reject_unknown_fmt' => $blank,
        'attestation_anchors' => ['defaults' => $blank, 'paths' => $blank],
        'attestation_clock_skew' => $blank,
        'aaguids' => ['allowed' => $blank],
        'user' => ['handle_column' => $blank, 'handle_bytes' => $blank, 'name_attribute' => $blank, 'display_name_attribute' => $blank],
    ]);
    $defaults = PasskeyConfig::fromArray([]);

    expect($config)->toEqual($defaults)
        ->and($config->rpName)->toBe('Laravel')
        ->and($config->attestationAnchorDefaults)->toBeTrue()
        ->and($config->userHandleColumn)->toBe('passkey_user_handle');
})->with(['empty' => [''], 'whitespace' => ['  ']]);

it('reads a blank relying-party name as the app name (strict config)', function (): void {
    expect(PasskeyConfig::fromArray(['rp' => ['name' => '']], appName: 'Acme')->rpName)->toBe('Acme')
        ->and(PasskeyConfig::fromArray([], appName: ' ')->rpName)->toBe('Laravel')
        ->and(PasskeyConfig::fromArray(['rp' => ['name' => 'Shop']], appName: 'Acme')->rpName)->toBe('Shop');
});

it('hands raw env integers to the strict reader through the shipped config (strict config)', function (): void {
    $_SERVER['PASSKEYS_TIMEOUT_MS'] = 'five';

    try {
        /** @var array<string, mixed> $shipped */
        $shipped = require __DIR__.'/../../../config/passkeys.php';
    } finally {
        unset($_SERVER['PASSKEYS_TIMEOUT_MS']);
    }

    expect($shipped['timeout_ms'])->toBe('five')
        ->and(fn (): PasskeyConfig => PasskeyConfig::fromArray($shipped))->toThrow(InvalidConfiguration::class, 'passkeys.timeout_ms');
});
