<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Events;

use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Fired after a credential is revoked (soft-deleted), e.g. to notify the owner or
 * end sessions that were established with it.
 */
final class PasskeyRevoked
{
    public function __construct(
        public readonly Passkey $passkey,
    ) {}
}
