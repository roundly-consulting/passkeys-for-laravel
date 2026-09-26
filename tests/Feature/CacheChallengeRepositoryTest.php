<?php

declare(strict_types=1);

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Store;
use Illuminate\Support\Carbon;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Repositories\CacheChallengeRepository;

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

/**
 * Laravel's `Repository::pull()` is a get followed by a forget — two round trips. A second
 * redemption of the same ceremony landing between them (two requests racing one captured
 * assertion) must not also receive the challenge: single-use is the whole guarantee.
 */
it('hands a challenge to exactly one of two racing redemptions', function (): void {
    $store = new class extends ArrayStore
    {
        /** @var (Closure(): void)|null */
        public ?Closure $race = null;

        public function get($key): mixed
        {
            $value = parent::get($key);

            // The racing request runs after this read and before the caller's forget.
            if ($this->race !== null && str_starts_with((string) $key, 'passkeys:challenge:')) {
                $race = $this->race;
                $this->race = null;
                $race();
            }

            return $value;
        }
    };

    $factory = new class($store) implements CacheFactory
    {
        public function __construct(private readonly ArrayStore $store) {}

        public function store($name = null): CacheRepository
        {
            return new CacheRepository($this->store);
        }
    };

    $repository = new CacheChallengeRepository($factory);
    $repository->put('raced', challenge('once'), 60);

    $racer = 'untouched';
    $store->race = function () use ($repository, &$racer): void {
        $racer = $repository->pull('raced');
    };

    $winner = $repository->pull('raced');

    expect($winner?->challenge)->toBe('once')
        ->and($racer)->toBeNull()
        ->and($repository->pull('raced'))->toBeNull();
});

it('still redeems once on a custom store that offers no locks', function (): void {
    $store = new class implements Store
    {
        private ArrayStore $inner;

        public function __construct()
        {
            $this->inner = new ArrayStore;
        }

        public function get($key): mixed
        {
            return $this->inner->get($key);
        }

        public function many(array $keys): array
        {
            return $this->inner->many($keys);
        }

        public function put($key, $value, $seconds): bool
        {
            return $this->inner->put($key, $value, $seconds);
        }

        public function putMany(array $values, $seconds): bool
        {
            return $this->inner->putMany($values, $seconds);
        }

        public function increment($key, $value = 1): int|bool
        {
            return $this->inner->increment($key, $value);
        }

        public function decrement($key, $value = 1): int|bool
        {
            return $this->inner->decrement($key, $value);
        }

        public function forever($key, $value): bool
        {
            return $this->inner->forever($key, $value);
        }

        public function touch($key, $seconds): bool
        {
            return $this->inner->touch($key, $seconds);
        }

        public function forget($key): bool
        {
            return $this->inner->forget($key);
        }

        public function flush(): bool
        {
            return $this->inner->flush();
        }

        public function getPrefix(): string
        {
            return '';
        }
    };

    $factory = new class($store) implements CacheFactory
    {
        public function __construct(private readonly Store $store) {}

        public function store($name = null): CacheRepository
        {
            return new CacheRepository($this->store);
        }
    };

    $repository = new CacheChallengeRepository($factory);
    $repository->put('lockless', challenge('plain'), 60);

    expect($store)->not->toBeInstanceOf(LockProvider::class)
        ->and($repository->pull('lockless')?->challenge)->toBe('plain')
        ->and($repository->pull('lockless'))->toBeNull();
});
