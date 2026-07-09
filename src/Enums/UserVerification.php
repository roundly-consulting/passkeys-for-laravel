<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The WebAuthn user-verification requirement for a ceremony.
 */
enum UserVerification: string
{
    use Helpers;

    case Required = 'required';
    case Preferred = 'preferred';
    case Discouraged = 'discouraged';
}
