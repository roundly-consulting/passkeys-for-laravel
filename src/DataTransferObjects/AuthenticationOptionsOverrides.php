<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Passkeys\Enums\UserVerification;

/**
 * Optional per-call knobs for an authentication-options request. Null members fall
 * back to the configured defaults. The user-verification requirement is stored with
 * the challenge, so the verifier enforces exactly what the options promised — a
 * step-up ceremony can demand `required` while the global default stays `preferred`.
 */
final readonly class AuthenticationOptionsOverrides
{
    public function __construct(
        public ?UserVerification $userVerification = null,
        public ?int $timeoutMs = null,
    ) {}
}
