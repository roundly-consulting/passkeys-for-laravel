<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The WebAuthn attestation-conveyance preference sent in creation options.
 */
enum AttestationConveyance: string
{
    use Helpers;

    case None = 'none';
    case Indirect = 'indirect';
    case Direct = 'direct';
}
