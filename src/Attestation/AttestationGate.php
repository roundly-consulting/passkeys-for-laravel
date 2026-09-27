<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\Enums\AttestationTrust;
use RoundlyConsulting\Passkeys\Enums\AttestationType;
use RoundlyConsulting\Passkeys\Exceptions\AttestationRequired;
use RoundlyConsulting\Passkeys\Exceptions\AttestationUntrusted;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAttestationFormat;
use RoundlyConsulting\Passkeys\Support\Aaguid;

/**
 * The attestation TRUST policy — the one thing the ceremony is bound to.
 *
 * Format verifiers prove maths; this gate decides what the proof is worth. The
 * ladder is monotone (WebAuthn §6.5.4, and this package's §7 matrix):
 *
 *   Ignore        record the format, read nothing. The DEFAULT, and it
 *                 short-circuits before any verifier runs — a host that does not
 *                 opt in sees no behaviour change whatsoever.
 *                 (With reject_unknown_fmt: the format must be one we know AND
 *                 its maths must hold. Anchors are still not consulted.)
 *   SelfAttested  the maths must hold — signature, chain linkage, certificate
 *                 validity dates. Anchoring is WAIVED, so self-attestation and an
 *                 un-anchored batch certificate both pass.
 *   Basic         the maths must hold AND the chain must reach a configured
 *                 anchor. Self-attestation is refused.
 *
 * Certificate validity dates are checked wherever a chain is checked: a lapsed
 * batch certificate is a fact the relying party should not silently bless. The
 * ANCHOR's own dates are not checked — a trust anchor is trusted because it is
 * configured, not because it is unexpired.
 */
final readonly class AttestationGate implements AttestationVerifier
{
    public function __construct(
        private AttestationVerifierRegistry $registry,
        private AttestationAnchors $anchors,
        private PasskeyConfig $config,
    ) {}

    /**
     * @throws PasskeyException
     */
    public function verify(
        AttestationObject $attestation,
        AuthenticatorData $authenticatorData,
        string $clientDataHash,
    ): AttestationResult {
        $format = $attestation->format;
        $trust = $this->config->attestationTrust;

        // The default posture. Byte-for-byte what this package did before any
        // attestation verifier existed: the format is recorded, nothing is read.
        // A configured allow-list still applies — it judges the asserted AAGUID,
        // not the statement, and is empty (a no-op) unless the host sets it.
        if ($trust === AttestationTrust::Ignore && ! $this->config->rejectUnknownFmt) {
            $this->assertAaguidAllowed($authenticatorData);

            return AttestationResult::none($format);
        }

        $verifier = $this->registry->for($format)
            ?? throw UnsupportedAttestationFormat::forFormat($format, $this->registry->formats());

        $result = $verifier->verify($attestation, $authenticatorData, $clientDataHash);

        if ($trust !== AttestationTrust::Ignore) {
            $this->applyLadder($result, $trust, $format);
        }

        $this->assertAaguidAllowed($authenticatorData);

        return $result;
    }

    /**
     * @throws PasskeyException
     */
    private function applyLadder(AttestationResult $result, AttestationTrust $trust, string $format): void
    {
        if ($result->type === AttestationType::None) {
            throw AttestationRequired::statementMissing($trust->value, $format);
        }

        if ($result->trustPath === null) {
            // Self-attestation. Sound, but it proves nothing about the hardware.
            if ($trust === AttestationTrust::Basic) {
                throw AttestationUntrusted::selfAttestationRejected($format);
            }

            return;
        }

        $this->assertSoundChain($result->trustPath, $format);

        if ($trust === AttestationTrust::Basic) {
            $this->assertAnchored($result->trustPath, $format);
        }
    }

    /**
     * Linkage and validity dates — checked under SelfAttested too, because that
     * tier waives ANCHORING, not correctness.
     *
     * @throws AttestationUntrusted
     */
    private function assertSoundChain(Chain $path, string $format): void
    {
        if (count($path) > 1 && ! $path->isLinked()) {
            throw AttestationUntrusted::chainNotLinked($format);
        }

        $leeway = $this->config->attestationClockSkew;

        foreach ($path as $certificate) {
            $this->assertInDate($certificate, $leeway);
        }
    }

    /**
     * @throws AttestationUntrusted
     */
    private function assertInDate(Certificate $certificate, int $leeway): void
    {
        $subject = $certificate->subject()->toString();

        if ($certificate->isExpiredAt(null, $leeway)) {
            throw AttestationUntrusted::certificateExpired(
                $subject,
                $certificate->notAfter()->toIso8601ZuluString(),
                $leeway,
            );
        }

        if ($certificate->isNotYetValidAt(null, $leeway)) {
            throw AttestationUntrusted::certificateNotYetValid(
                $subject,
                $certificate->notBefore()->toIso8601ZuluString(),
                $leeway,
            );
        }
    }

    /**
     * @throws PasskeyException
     */
    private function assertAnchored(Chain $path, string $format): void
    {
        // x5c usually omits the root, so the top certificate's ISSUER is the CA
        // the operator has to fetch — both refusals name it.
        $root = $path->root();

        if ($this->anchors->for($format) === []) {
            throw AttestationUntrusted::noAnchorsConfigured($format, $root->issuer()->toString());
        }

        if ($this->anchors->anchorFor($path, $format) !== null) {
            return;
        }

        throw AttestationUntrusted::rootNotAnchored(
            $format,
            $root->subject()->toString(),
            $root->fingerprint(),
            $root->issuer()->toString(),
        );
    }

    /**
     * The AAGUID allow-list. Only PROVEN under Basic (the certificate binds it);
     * under the lower tiers the authenticator merely asserts it — the list is
     * enforced regardless when configured, which the docs say plainly.
     *
     * @throws AttestationUntrusted
     */
    private function assertAaguidAllowed(AuthenticatorData $authenticatorData): void
    {
        $allowed = $this->config->allowedAaguids;

        if ($allowed === []) {
            return;
        }

        $aaguid = Aaguid::format($authenticatorData->aaguid);

        if ($aaguid === null || ! in_array($aaguid, $allowed, true)) {
            throw AttestationUntrusted::aaguidNotAllowed($aaguid);
        }
    }
}
