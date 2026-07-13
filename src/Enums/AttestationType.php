<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The grade of proof a verified attestation statement established
 * (WebAuthn Level 3 §6.5.4).
 *
 * - None:   no attestation was presented (or none was verified).
 * - Self:   the statement is signed by the credential key itself — it proves the
 *           key can sign, and nothing about the hardware holding it.
 * - Basic:  signed by a batch certificate. Basic and AttCA are indistinguishable
 *           to a relying party, so an x5c-chained `packed`/`android-key`
 *           statement is reported as Basic.
 * - AttCa:  an attestation CA (privacy CA) vouched for the key — a TPM AIK.
 * - AnonCa: an anonymisation CA issued a per-registration certificate (Apple).
 */
enum AttestationType: string
{
    use Helpers;

    case None = 'none';
    case Self = 'self';
    case Basic = 'basic';
    case AttCa = 'attca';
    case AnonCa = 'anonca';

    /**
     * Whether this type carries a certificate chain that policy can anchor.
     */
    public function isChained(): bool
    {
        return match ($this) {
            self::None, self::Self => false,
            self::Basic, self::AttCa, self::AnonCa => true,
        };
    }
}
