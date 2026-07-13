<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

/**
 * The attestation formats this relying party can verify, keyed by their WebAuthn
 * `fmt` string. A host that ships its own format rebinds this in the container.
 */
final readonly class AttestationVerifierRegistry
{
    /**
     * @param  array<string, AttestationVerifier>  $verifiers  fmt => verifier
     */
    public function __construct(private array $verifiers) {}

    public function for(string $format): ?AttestationVerifier
    {
        return $this->verifiers[$format] ?? null;
    }

    /**
     * The supported formats, for the "…is not supported" message.
     *
     * @return list<string>
     */
    public function formats(): array
    {
        return array_keys($this->verifiers);
    }
}
