<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\DataTransferObjects\ParsedAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;

/**
 * Verifies (or deliberately ignores) an attestation statement during
 * registration. Phase 1 ships the `none`/ignore strategy; a trust-policy
 * verifier can be bound in its place without touching the ceremony action.
 */
interface AttestationVerifier
{
    /**
     * @throws PasskeyException
     */
    public function verify(
        AttestationObject $attestation,
        ParsedAuthenticatorData $authenticatorData,
        string $clientDataHash,
    ): void;
}
