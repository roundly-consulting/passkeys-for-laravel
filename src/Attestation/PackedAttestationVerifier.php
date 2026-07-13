<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Signature\Key\PublicKey;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Passkeys\Attestation\Statements\PackedStatement;
use RoundlyConsulting\Passkeys\Attestation\Support\CertificateExtensions;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Enums\AttestationType;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAttestation;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Support\CredentialCrypto;

/**
 * The `packed` attestation format (WebAuthn §8.2) — what CTAP2 security keys and
 * most platform authenticators send under `direct` conveyance.
 *
 * Two shapes, both handled:
 *  - **x5c present** — the statement is signed by a batch (attestation)
 *    certificate. Basic and AttCA are indistinguishable to a relying party, so
 *    the result is reported as {@see AttestationType::Basic}.
 *  - **x5c absent** — SELF-attestation: the signature is made with the credential
 *    key itself, so it proves the key can sign and nothing more.
 *
 * Whether either is acceptable is the gate's ruling. This class only does maths.
 */
final readonly class PackedAttestationVerifier implements AttestationVerifier
{
    private const string ATTESTATION_SUBJECT_OU = 'Authenticator Attestation';

    public function __construct(
        private CredentialCrypto $crypto,
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
        $statement = PackedStatement::fromAttestationObject($attestation);
        $signedData = $attestation->authenticatorData.$clientDataHash;

        return $statement->isSelfAttested()
            ? $this->verifySelf($statement, $authenticatorData, $signedData)
            : $this->verifyChained($statement, $authenticatorData, $signedData);
    }

    /**
     * Self-attestation: the credential key signs its own registration. There is
     * no certificate anywhere in this path.
     *
     * @throws PasskeyException
     */
    private function verifySelf(
        PackedStatement $statement,
        AuthenticatorData $authenticatorData,
        string $signedData,
    ): AttestationResult {
        $credentialKey = $authenticatorData->coseKey;

        if ($credentialKey === null) {
            throw InvalidAuthenticatorData::attestedDataMissing();
        }

        $this->assertAlgorithm($statement, $credentialKey);
        $this->assertSignature($credentialKey, $signedData, $statement->signature);

        return AttestationResult::self('packed');
    }

    /**
     * @throws PasskeyException
     */
    private function verifyChained(
        PackedStatement $statement,
        AuthenticatorData $authenticatorData,
        string $signedData,
    ): AttestationResult {
        $chain = $this->chain($statement);
        $leaf = $chain->leaf();

        try {
            $leafKey = $leaf->publicKey();
        } catch (CryptoException $e) {
            throw InvalidAttestation::malformedStatement('packed', $e->getMessage());
        }

        // The statement names an algorithm; the key IS one. They must agree, or a
        // caller is being invited to verify under something the key never signed.
        $this->assertAlgorithm($statement, $leafKey);
        $this->assertSignature($leafKey, $signedData, $statement->signature);
        $this->assertCertificateRequirements($leaf);
        $this->assertAaguidExtension($leaf, $authenticatorData);

        return AttestationResult::chained('packed', AttestationType::Basic, $chain);
    }

    /**
     * Build the trust path from the statement's RAW DER entries.
     *
     * NOT `Chain::fromX5c()`: that decodes base64, which is right for a JOSE x5c
     * header and wrong for CBOR, whose x5c carries the certificate bytes
     * themselves.
     *
     * @throws InvalidAttestation
     */
    private function chain(PackedStatement $statement): Chain
    {
        try {
            return new Chain(array_map(
                static fn (string $der): Certificate => Certificate::fromDer($der),
                $statement->x5c,
            ));
        } catch (CryptoException $e) {
            throw InvalidAttestation::malformedStatement('packed', $e->getMessage());
        }
    }

    /**
     * @throws PasskeyException
     */
    private function assertAlgorithm(PackedStatement $statement, PublicKey $key): void
    {
        $actual = $this->crypto->coseAlgorithm($key)->value;

        if ($statement->algorithm !== $actual) {
            throw InvalidAttestation::algorithmMismatch('packed', $statement->algorithm, $actual);
        }
    }

    /**
     * @throws PasskeyException
     */
    private function assertSignature(PublicKey $key, string $signedData, string $signature): void
    {
        if (! $this->crypto->verify($key, $signedData, $signature)) {
            throw InvalidAttestation::signatureMismatch('packed');
        }
    }

    /**
     * WebAuthn §8.2.1 — the attestation certificate's shape.
     *
     * `basicConstraints` is read as RFC 5280 defines it: an absent extension, or
     * one whose `cA` is absent/false, is an end entity. Only an explicit CA:TRUE
     * is refused — a CA certificate must never sign an attestation directly.
     *
     * @throws InvalidAttestation
     */
    private function assertCertificateRequirements(Certificate $leaf): void
    {
        if ($leaf->version() !== 3) {
            throw InvalidAttestation::certificateRequirement('packed', 'the attestation certificate must be X.509 version 3');
        }

        if ($leaf->subject()->organizationalUnit !== self::ATTESTATION_SUBJECT_OU) {
            throw InvalidAttestation::certificateRequirement(
                'packed',
                'the attestation certificate\'s subject OU must be "'.self::ATTESTATION_SUBJECT_OU.'"',
            );
        }

        if ($this->extensions->isCertificateAuthority($leaf)) {
            throw InvalidAttestation::certificateRequirement('packed', 'the attestation certificate must not be a CA (basicConstraints CA:FALSE)');
        }
    }

    /**
     * The optional id-fido-gen-ce-aaguid extension binds the certificate to one
     * authenticator model. When it is there it must agree with the authenticator
     * data, or the model the credential claims to be is not the model that signed.
     *
     * @throws InvalidAttestation
     */
    private function assertAaguidExtension(Certificate $leaf, AuthenticatorData $authenticatorData): void
    {
        try {
            $certified = $this->extensions->fidoAaguid($leaf);
        } catch (CryptoException $e) {
            throw InvalidAttestation::malformedStatement('packed', 'the id-fido-gen-ce-aaguid extension is not an OCTET STRING ('.$e->getMessage().')');
        }

        if ($certified === null) {
            return;
        }

        if ($this->extensions->fidoAaguidIsCritical($leaf)) {
            throw InvalidAttestation::certificateRequirement('packed', 'the id-fido-gen-ce-aaguid extension must not be critical');
        }

        if (strlen($certified) !== 16 || ! ConstantTime::equals($certified, (string) $authenticatorData->aaguid)) {
            throw InvalidAttestation::aaguidMismatch();
        }
    }
}
