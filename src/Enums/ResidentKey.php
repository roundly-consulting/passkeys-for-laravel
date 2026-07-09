<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The WebAuthn resident-key (discoverable-credential) requirement for a
 * registration ceremony.
 */
enum ResidentKey: string
{
    use Helpers;

    case Required = 'required';
    case Preferred = 'preferred';
    case Discouraged = 'discouraged';

    /**
     * The legacy boolean the spec still emits alongside residentKey.
     */
    public function requireResidentKey(): bool
    {
        return $this === self::Required;
    }
}
