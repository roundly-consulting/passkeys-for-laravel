<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Repositories;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\LockProvider;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;

/**
 * Cache-backed challenge store. `pull` fetches and forgets under the store's own
 * lock, so a challenge can only ever be redeemed once (replay-safe) even by two
 * racing requests; the TTL bounds how long an unfinished ceremony stays valid.
 */
final class CacheChallengeRepository implements ChallengeRepository
{
    private const PREFIX = 'passkeys:challenge:';

    private const LOCK_PREFIX = 'passkeys:challenge-lock:';

    /** Seconds a crashed redemption can hold the lock; the critical section is one read + one delete. */
    private const LOCK_SECONDS = 10;

    public function __construct(
        private readonly CacheFactory $cache,
        private readonly ?string $store = null,
    ) {}

    public function put(string $ceremonyId, ChallengeData $challenge, int $ttl): void
    {
        $this->cache->store($this->store)->put(
            self::PREFIX.$ceremonyId,
            $challenge->toArray(),
            $ttl,
        );
    }

    public function pull(string $ceremonyId): ?ChallengeData
    {
        $repository = $this->cache->store($this->store);
        $key = self::PREFIX.$ceremonyId;
        $store = $repository->getStore();

        // Repository::pull() is a get followed by a forget — two round trips, so two
        // requests racing one ceremony could both read it. Under the lock exactly one
        // reads-and-forgets; a caller that cannot take it is racing a redemption already
        // in flight and gets nothing, exactly as if the challenge were consumed.
        $data = $store instanceof LockProvider
            ? $store->lock(self::LOCK_PREFIX.$ceremonyId, self::LOCK_SECONDS)->get(static fn (): mixed => $repository->pull($key))
            : $repository->pull($key);

        if (! is_array($data)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        return ChallengeData::fromArray($data);
    }
}
