<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;

/**
 * A parsed COSE public key, reduced to the material a signature verifier needs.
 *
 * For ES256/RS256 the SPKI PEM is pre-assembled for ext-openssl. For EdDSA the
 * raw 32-byte Edwards public key is kept for ext-sodium verification.
 */
final readonly class CoseKeyData
{
    public function __construct(
        public CoseAlgorithm $algorithm,
        public ?string $pem = null,
        public ?string $edwardsPublicKey = null,
    ) {}
}
