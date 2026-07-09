<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

/**
 * The parsed fields of an authenticatorData structure. Attested credential data
 * (aaguid, credentialId, COSE key) is only present on a registration response.
 */
final readonly class ParsedAuthenticatorData
{
    public function __construct(
        public string $rpIdHash,
        public AuthenticatorFlags $flags,
        public int $signCount,
        public ?string $aaguid = null,
        public ?string $credentialId = null,
        public ?CoseKeyData $coseKey = null,
        public ?string $coseKeyBytes = null,
    ) {}
}
