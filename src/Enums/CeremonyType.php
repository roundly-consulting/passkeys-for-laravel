<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The WebAuthn ceremony a stored challenge was minted for. Persisting it on the
 * challenge lets the verifier reject a challenge presented to the wrong ceremony
 * (registration vs authentication), independent of the clientData.type check.
 */
enum CeremonyType: string
{
    use Helpers;

    case Registration = 'registration';
    case Authentication = 'authentication';
}
