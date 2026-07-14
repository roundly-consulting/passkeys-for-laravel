<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;

/**
 * The Phase 1 "ignore" strategy: the attestation format is recorded on the
 * stored credential, but the statement itself is not cryptographically checked.
 * When `reject_unknown_fmt` is enabled, only the `none` format is accepted.
 */
final class NoneAttestationVerifier implements AttestationVerifier
{
    public function __construct(
        private readonly bool $rejectUnknownFormat = false,
    ) {}

    public function verify(
        AttestationObject $attestation,
        AuthenticatorData $authenticatorData,
        string $clientDataHash,
    ): void {
        if ($this->rejectUnknownFormat && $attestation->format !== 'none') {
            throw InvalidClientData::malformed();
        }
    }
}
