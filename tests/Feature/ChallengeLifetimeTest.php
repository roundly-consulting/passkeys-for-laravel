<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationOptionsOverrides;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationOptionsOverrides;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\PasskeyManager;
use RoundlyConsulting\Passkeys\Tests\Support\User;

/**
 * The browser is told how long it has (`timeout`); the server-side challenge must live at
 * least that long, or a ceremony the user finishes inside the promised window is refused
 * as expired. `challenge.ttl` stays the floor.
 */
function lifetimeChallengeAlive(string $ceremonyId, int $afterSeconds): bool
{
    Carbon::setTestNow(Carbon::now()->addSeconds($afterSeconds));

    try {
        return app(ChallengeRepository::class)->pull($ceremonyId) !== null;
    } finally {
        Carbon::setTestNow();
    }
}

function lifetimeUseConfig(int $timeoutMs, int $ttl): void
{
    config()->set('passkeys.timeout_ms', $timeoutMs);
    config()->set('passkeys.challenge.ttl', $ttl);

    app()->forgetInstance(PasskeyConfig::class);
    app()->forgetInstance(PasskeyManager::class);
    app()->forgetInstance(PasskeyService::class);
    Passkeys::clearResolvedInstances();
}

beforeEach(function (): void {
    Carbon::setTestNow(Carbon::now());
    $this->user = User::query()->create(['name' => 'Tia', 'email' => 'tia@example.com']);
});

afterEach(function (): void {
    Carbon::setTestNow();
});

it('keeps an assertion challenge alive for a per-call timeout longer than the ttl', function (): void {
    $options = Passkeys::authenticationOptions(overrides: new AuthenticationOptionsOverrides(timeoutMs: 180_000));

    expect(lifetimeChallengeAlive($options->ceremonyId, 170))->toBeTrue();
});

it('keeps a registration challenge alive for a per-call timeout longer than the ttl', function (): void {
    $options = Passkeys::registrationOptions($this->user, new RegistrationOptionsOverrides(timeoutMs: 180_000));

    expect(lifetimeChallengeAlive($options->ceremonyId, 170))->toBeTrue();
});

it('still expires the challenge once the promised timeout has passed', function (): void {
    $options = Passkeys::authenticationOptions(overrides: new AuthenticationOptionsOverrides(timeoutMs: 180_000));

    expect(lifetimeChallengeAlive($options->ceremonyId, 181))->toBeFalse();
});

it('rounds a sub-second timeout up to the next whole second', function (): void {
    lifetimeUseConfig(timeoutMs: 1_000, ttl: 1);

    $options = Passkeys::authenticationOptions(overrides: new AuthenticationOptionsOverrides(timeoutMs: 90_500));

    expect(lifetimeChallengeAlive($options->ceremonyId, 90))->toBeTrue();
});

it('honours a configured timeout longer than the ttl', function (): void {
    lifetimeUseConfig(timeoutMs: 120_000, ttl: 60);

    $options = Passkeys::authenticationOptions();

    expect($options->timeoutMs)->toBe(120_000)
        ->and(lifetimeChallengeAlive($options->ceremonyId, 110))->toBeTrue();
});

it('keeps the ttl as the floor under a shorter timeout', function (): void {
    lifetimeUseConfig(timeoutMs: 60_000, ttl: 300);

    $options = Passkeys::authenticationOptions(overrides: new AuthenticationOptionsOverrides(timeoutMs: 15_000));

    expect(lifetimeChallengeAlive($options->ceremonyId, 200))->toBeTrue();
});

it('expires at the ttl when the timeout matches it', function (): void {
    $options = Passkeys::authenticationOptions();

    expect(lifetimeChallengeAlive($options->ceremonyId, 61))->toBeFalse();
});
