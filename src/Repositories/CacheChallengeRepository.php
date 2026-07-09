<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Repositories;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;

/**
 * Cache-backed challenge store. `pull` fetches and forgets in one call, so a
 * challenge can only ever be redeemed once (replay-safe); the TTL bounds how
 * long an unfinished ceremony stays valid.
 */
final class CacheChallengeRepository implements ChallengeRepository
{
    private const PREFIX = 'passkeys:challenge:';

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
        $data = $this->cache->store($this->store)->pull(self::PREFIX.$ceremonyId);

        if (! is_array($data)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        return ChallengeData::fromArray($data);
    }
}
