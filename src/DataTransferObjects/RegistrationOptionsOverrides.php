<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\UserVerification;

/**
 * Optional per-call knobs for a registration-options request. Null members fall
 * back to the configured defaults.
 */
final readonly class RegistrationOptionsOverrides
{
    public function __construct(
        public ?UserVerification $userVerification = null,
        public ?AttestationConveyance $attestation = null,
        public ?int $timeoutMs = null,
    ) {}
}
