<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * COSE algorithm identifiers (IANA COSE registry) supported by the relying party.
 */
enum CoseAlgorithm: int
{
    use Helpers;

    case ES256 = -7;
    case EdDSA = -8;
    case RS256 = -257;

    /**
     * The OpenSSL digest algorithm used when verifying a signature for this COSE alg.
     */
    public function opensslAlgorithm(): int
    {
        return match ($this) {
            self::ES256, self::RS256 => OPENSSL_ALGO_SHA256,
            self::EdDSA => 0, // verified via ext-sodium, not OpenSSL
        };
    }
}
