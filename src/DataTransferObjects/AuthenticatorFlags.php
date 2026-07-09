<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

/**
 * The decoded authenticator-data flag bits.
 *
 * UP = user present (bit 0), UV = user verified (bit 2), BE = backup eligible
 * (bit 3), BS = backup state (bit 4), AT = attested credential data present
 * (bit 6), ED = extension data present (bit 7).
 */
final readonly class AuthenticatorFlags
{
    public function __construct(
        public bool $userPresent,
        public bool $userVerified,
        public bool $backupEligible,
        public bool $backupState,
        public bool $attestedCredentialData,
        public bool $extensionData,
    ) {}

    public static function fromByte(int $byte): self
    {
        return new self(
            userPresent: (bool) ($byte & 0x01),
            userVerified: (bool) ($byte & 0x04),
            backupEligible: (bool) ($byte & 0x08),
            backupState: (bool) ($byte & 0x10),
            attestedCredentialData: (bool) ($byte & 0x40),
            extensionData: (bool) ($byte & 0x80),
        );
    }
}
