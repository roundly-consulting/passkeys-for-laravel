<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The WebAuthn authenticator-attachment preference for a registration ceremony:
 * a platform (built-in) authenticator or a cross-platform (roaming) one.
 */
enum AuthenticatorAttachment: string
{
    use Helpers;

    case Platform = 'platform';
    case CrossPlatform = 'cross-platform';
}
