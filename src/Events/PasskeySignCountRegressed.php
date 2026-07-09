<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Events;

use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Fired when an authenticator reports a signature counter that did not advance
 * and the sign-count policy is `flag`. Hosts listen to record the anomaly.
 */
final class PasskeySignCountRegressed
{
    public function __construct(
        public readonly Passkey $passkey,
        public readonly int $stored,
        public readonly int $received,
    ) {}
}
