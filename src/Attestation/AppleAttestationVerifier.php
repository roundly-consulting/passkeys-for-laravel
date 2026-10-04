<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

use RoundlyConsulting\Crypto\Asn1\MalformedDerException;
use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Passkeys\Attestation\Statements\AppleStatement;
use RoundlyConsulting\Passkeys\Attestation\Support\CertificateExtensions;
use RoundlyConsulting\Passkeys\Attestation\Support\KeysMatch;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Enums\AttestationType;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAttestation;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;

/**
 * The `apple` attestation format (WebAuthn §8.8) — what Apple's platform
 * authenticators send under `direct` conveyance.
 *
 * Apple attests ANONYMOUSLY: the statement carries a certificate path and nothing
 * else — no signature, no algorithm. Nothing about the device is revealed beyond
 * "an Apple authenticator made this", which is why the result is
 * {@see AttestationType::AnonCa} and never Basic.
 *
 * With no signature over the authenticator data, the binding to THIS ceremony is
 * made of two facts, and both are checked here:
 *
 *  1. the credential certificate carries a nonce extension holding
 *     `SHA-256(authenticatorData ‖ clientDataHash)` — Apple's CA issues the
 *     certificate over the nonce the authenticator presented, so a statement
 *     replayed from another ceremony carries the wrong hash and is refused;
 *  2. the certificate's subject public key IS the credential public key — so a
 *     genuine path cannot be lifted onto somebody else's credential.
 *
 * Whether the path is acceptable — whether it reaches Apple's WebAuthn Root CA —
 * is the gate's ruling, not this class's. This class only does maths.
 */
final readonly class AppleAttestationVerifier implements AttestationVerifier
{
    public function __construct(
        private Digest $digest = new Digest,
        private CertificateExtensions $extensions = new CertificateExtensions,
    ) {}

    /**
     * @throws PasskeyException
     */
    public function verify(
        AttestationObject $attestation,
        AuthenticatorData $authenticatorData,
        string $clientDataHash,
    ): AttestationResult {
        $statement = AppleStatement::fromAttestationObject($attestation);

        $credentialKey = $authenticatorData->coseKey;

        if ($credentialKey === null) {
            throw InvalidAuthenticatorData::attestedDataMissing();
        }

        $chain = $this->chain($statement);
        $credentialCertificate = $chain->leaf();

        $this->assertNonce($credentialCertificate, $attestation->authenticatorData, $clientDataHash);

        try {
            $certifiedKey = $credentialCertificate->publicKey();
        } catch (CryptoException $e) {
            throw InvalidAttestation::malformedStatement('apple', 'certificate_key_unreadable', $e);
        }

        if (! KeysMatch::check($certifiedKey, $credentialKey)) {
            throw InvalidAttestation::credentialKeyMismatch('apple');
        }

        return AttestationResult::chained('apple', AttestationType::AnonCa, $chain);
    }

    /**
     * Build the trust path from the statement's RAW DER entries.
     *
     * NOT the base64 x5c helper: CBOR carries the certificate bytes themselves,
     * and Apple omits the root, so the path routinely ends at an intermediate that
     * the anchor store completes.
     *
     * @throws InvalidAttestation
     */
    private function chain(AppleStatement $statement): Chain
    {
        $certificates = [];

        foreach ($statement->x5c as $der) {
            try {
                $certificates[] = Certificate::fromDer($der);
            } catch (CryptoException $e) {
                throw InvalidAttestation::malformedStatement('apple', 'x5c_entry_unreadable', $e);
            }
        }

        try {
            return new Chain($certificates);
        } catch (CryptoException $e) {
            throw InvalidAttestation::malformedStatement('apple', 'x5c_too_long', $e);
        }
    }

    /**
     * The whole security property of this format: the certificate's nonce must be
     * the hash of the very bytes this ceremony produced. Tamper with either the
     * authenticator data or the client data and the hash moves.
     *
     * @throws InvalidAttestation
     */
    private function assertNonce(Certificate $credentialCertificate, string $authenticatorData, string $clientDataHash): void
    {
        try {
            $certified = $this->extensions->appleNonce($credentialCertificate);
        } catch (MalformedDerException $e) {
            throw InvalidAttestation::malformedStatement('apple', 'apple_nonce_extension_malformed', $e);
        }

        if ($certified === null) {
            throw InvalidAttestation::certificateRequirement('apple', 'apple_nonce_extension');
        }

        if (! ConstantTime::equals($certified, $this->digest->raw($authenticatorData.$clientDataHash))) {
            throw InvalidAttestation::appleNonceMismatch();
        }
    }
}
