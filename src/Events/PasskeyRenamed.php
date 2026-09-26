<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Events;

use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Fired after a credential's friendly name changes. The name is cosmetic — never a
 * verification input — so this is an audit signal, not a security one.
 */
final class PasskeyRenamed
{
    public function __construct(
        public readonly Passkey $passkey,
        public readonly ?string $previousName,
    ) {}
}
