<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Events;

use RoundlyConsulting\Passkeys\Models\Passkey;

final class PasskeyAuthenticated
{
    public function __construct(
        public readonly Passkey $passkey,
    ) {}
}
