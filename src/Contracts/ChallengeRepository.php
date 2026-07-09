<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Contracts;

use RoundlyConsulting\Passkeys\DataTransferObjects\ChallengeData;

/**
 * Single-use, TTL-bound storage for in-flight ceremony challenges.
 */
interface ChallengeRepository
{
    public function put(string $ceremonyId, ChallengeData $challenge, int $ttl): void;

    /**
     * Atomically fetch and forget the challenge for a ceremony. Returns null when
     * it is missing, expired, or already consumed (replay-safe).
     */
    public function pull(string $ceremonyId): ?ChallengeData;
}
