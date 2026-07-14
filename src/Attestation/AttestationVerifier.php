<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;

/**
 * Verifies (or deliberately ignores) an attestation statement during
 * registration. Phase 1 ships the `none`/ignore strategy; a trust-policy
 * verifier can be bound in its place without touching the ceremony action.
 *
 * Attestation is a *trust* decision, not an algorithm: it stays in this package
 * even though the primitives it would lean on live in crypto-for-laravel.
 */
interface AttestationVerifier
{
    /**
     * @throws PasskeyException
     */
    public function verify(
        AttestationObject $attestation,
        AuthenticatorData $authenticatorData,
        string $clientDataHash,
    ): void;
}
