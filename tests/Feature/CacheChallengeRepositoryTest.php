<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\Enums\UserVerification;

beforeEach(function (): void {
    $this->repository = app(ChallengeRepository::class);
});

function challenge(string $value = 'abc'): ChallengeData
{
    return new ChallengeData(
        challenge: $value,
        userVerification: UserVerification::Required,
        algorithms: [-7, -257],
        userHandle: 'handle',
    );
}

it('stores and returns a challenge exactly once', function (): void {
    $this->repository->put('ceremony-1', challenge('first'), 60);

    $pulled = $this->repository->pull('ceremony-1');

    expect($pulled)->not->toBeNull()
        ->and($pulled->challenge)->toBe('first')
        ->and($pulled->userVerification)->toBe(UserVerification::Required)
        ->and($pulled->algorithms)->toBe([-7, -257])
        ->and($pulled->userHandle)->toBe('handle');

    // Single-use: a second pull finds nothing (replay-safe).
    expect($this->repository->pull('ceremony-1'))->toBeNull();
});

it('returns null for an unknown ceremony id', function (): void {
    expect($this->repository->pull('missing'))->toBeNull();
});

it('expires a challenge after its ttl', function (): void {
    $this->repository->put('ceremony-2', challenge(), 60);

    Carbon::setTestNow(Carbon::now()->addSeconds(61));

    expect($this->repository->pull('ceremony-2'))->toBeNull();

    Carbon::setTestNow();
});

it('round-trips the challenge data through array serialisation', function (): void {
    $data = challenge('serialise');
    $restored = ChallengeData::fromArray($data->toArray());

    expect($restored->challenge)->toBe('serialise')
        ->and($restored->userVerification)->toBe(UserVerification::Required)
        ->and($restored->algorithms)->toBe([-7, -257]);
});

it('recovers gracefully from a corrupt cache entry', function (): void {
    cache()->store()->put('passkeys:challenge:corrupt', 'not-an-array', 60);

    expect($this->repository->pull('corrupt'))->toBeNull();
});
