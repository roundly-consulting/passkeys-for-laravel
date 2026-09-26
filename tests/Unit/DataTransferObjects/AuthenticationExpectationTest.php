<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationExpectation;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\User;

it('carries only a type for an owner-type expectation', function (): void {
    $expect = AuthenticationExpectation::ownerType('client');

    expect($expect->ownerType)->toBe('client')
        ->and($expect->ownerKey)->toBeNull();
});

it('carries the morph type and key of an exact owner', function (): void {
    $user = User::query()->create(['name' => 'Ada']);

    $expect = AuthenticationExpectation::owner($user);

    expect($expect->ownerType)->toBe($user->getMorphClass())
        ->and($expect->ownerKey)->toBe($user->getKey());
});

it('matches on type alone when no key is expected', function (): void {
    $passkey = Passkey::factory()->make(['authenticatable_type' => 'client', 'authenticatable_id' => 9]);

    expect(AuthenticationExpectation::ownerType('client')->matches($passkey))->toBeTrue()
        ->and(AuthenticationExpectation::ownerType('user')->matches($passkey))->toBeFalse();
});

it('compares owner keys as strings so int, numeric-string and uuid keys all work', function (): void {
    $user = User::query()->create(['name' => 'Ada']);

    $numericString = Passkey::factory()->make(['authenticatable_type' => $user->getMorphClass(), 'authenticatable_id' => (string) $user->getKey()]);
    $other = Passkey::factory()->make(['authenticatable_type' => $user->getMorphClass(), 'authenticatable_id' => $user->getKey() + 1]);

    expect(AuthenticationExpectation::owner($user)->matches($numericString))->toBeTrue()
        ->and(AuthenticationExpectation::owner($user)->matches($other))->toBeFalse();
});

it('defaults the authentication overrides to null members', function (): void {
    $overrides = new AuthenticationOptionsOverrides;

    expect($overrides->userVerification)->toBeNull()
        ->and($overrides->timeoutMs)->toBeNull();
});
