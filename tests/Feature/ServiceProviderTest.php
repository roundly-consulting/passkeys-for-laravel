<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifier;
use RoundlyConsulting\Passkeys\Attestation\NoneAttestationVerifier;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\PasskeyManager;
use RoundlyConsulting\Passkeys\Repositories\CacheChallengeRepository;

it('merges the package configuration', function (): void {
    expect(config('passkeys.table'))->toBe('passkeys')
        ->and(config('passkeys.sign_count_policy'))->toBe('flag');
});

it('binds the challenge repository to the cache-backed implementation', function (): void {
    expect(app(ChallengeRepository::class))->toBeInstanceOf(CacheChallengeRepository::class);
});

it('binds the attestation verifier to the none strategy', function (): void {
    expect(app(AttestationVerifier::class))->toBeInstanceOf(NoneAttestationVerifier::class);
});

it('resolves the typed config as a singleton', function (): void {
    expect(app(PasskeyConfig::class))
        ->toBeInstanceOf(PasskeyConfig::class)
        ->toBe(app(PasskeyConfig::class));
});

it('resolves the passkey manager as a singleton', function (): void {
    expect(app(PasskeyManager::class))->toBe(app(PasskeyManager::class));
});

it('registers the migration so the passkeys table exists', function (): void {
    expect(Schema::hasTable('passkeys'))->toBeTrue();
});

it('derives the rp id from the app url when none is configured', function (): void {
    $config = PasskeyConfig::fromArray([], 'https://derived.example');

    expect($config->rpId)->toBe('derived.example');
});
