<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * How the relying party treats the attestation statement of a registration.
 *
 * - Ignore: record the format, do not verify the statement (the default).
 * - Self:   verify a self-attestation signature with the credential key.
 * - Basic:  verify a basic attestation signature with the x5c leaf certificate.
 */
enum AttestationTrust: string
{
    use Helpers;

    case Ignore = 'ignore';
    case SelfAttested = 'self';
    case Basic = 'basic';
}
