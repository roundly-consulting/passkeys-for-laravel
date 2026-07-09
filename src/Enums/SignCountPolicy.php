<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * What to do when an authenticator reports a signature counter that did not
 * advance (a possible cloned-authenticator signal).
 *
 * - Reject: throw and abort the authentication.
 * - Flag:   fire an event and allow the authentication to proceed.
 */
enum SignCountPolicy: string
{
    use Helpers;

    case Reject = 'reject';
    case Flag = 'flag';
}
