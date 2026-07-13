<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Passkeys\Enums\AttestationType;

/**
 * What a format verifier's maths PROVED — never what policy makes of it.
 *
 * A verifier reports the format it ran, the grade of attestation the statement
 * established, and (when there is one) the certificate path it was signed under,
 * leaf first. Whether that path is acceptable is {@see AttestationGate}'s ruling.
 */
final readonly class AttestationResult
{
    public function __construct(
        public string $format,
        public AttestationType $type,
        public ?Chain $trustPath = null,
    ) {}

    /** No attestation was verified — the format was merely recorded. */
    public static function none(string $format): self
    {
        return new self($format, AttestationType::None);
    }

    /** The statement was signed by the credential key itself. */
    public static function self(string $format): self
    {
        return new self($format, AttestationType::Self);
    }

    /** The statement was signed under a certificate path. */
    public static function chained(string $format, AttestationType $type, Chain $trustPath): self
    {
        return new self($format, $type, $trustPath);
    }
}
