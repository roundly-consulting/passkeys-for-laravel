<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation\Support;

use RoundlyConsulting\Crypto\Asn1\DerDecoder;
use RoundlyConsulting\Crypto\Asn1\MalformedDerException;
use RoundlyConsulting\Crypto\Asn1\TagClass;
use RoundlyConsulting\Crypto\X509\Certificate;

/**
 * Reads the attestation-relevant X.509 extensions.
 *
 * Crypto hands back an extension's RAW DER and interprets nothing — what those
 * bytes MEAN is attestation domain, so the meaning is assigned here, with
 * crypto's strict DER decoder doing the parsing.
 */
final readonly class CertificateExtensions
{
    /** RFC 5280 §4.2.1.9 — basicConstraints. */
    public const string BASIC_CONSTRAINTS_OID = '2.5.29.19';

    /** RFC 5280 §4.2.1.3 — keyUsage. */
    public const string KEY_USAGE_OID = '2.5.29.15';

    /** WebAuthn §8.2.1 — id-fido-gen-ce-aaguid. */
    public const string FIDO_AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

    /**
     * WebAuthn §8.8 — Apple's anonymous-attestation nonce extension. Spelled out in
     * the nonce messages of every language file too.
     */
    public const string APPLE_NONCE_OID = '1.2.840.113635.100.8.2';

    public function __construct(private DerDecoder $decoder = new DerDecoder) {}

    /**
     * Whether the certificate asserts `CA:TRUE`.
     *
     * `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, … }` — the
     * DEFAULT means a CA:FALSE certificate encodes an EMPTY sequence, and an
     * absent extension is likewise not a CA. Only an explicit TRUE is a CA.
     */
    public function isCertificateAuthority(Certificate $certificate): bool
    {
        try {
            return $this->assertsCa($certificate);
        } catch (MalformedDerException) {
            // A basicConstraints extension we cannot read is not a licence to
            // treat the certificate as an end entity.
            return true;
        }
    }

    /**
     * Whether the certificate may sign OTHER certificates in a path — RFC 5280
     * §6.1.4 (k) and (n): basicConstraints asserts `CA:TRUE`, and a keyUsage
     * extension, when present, asserts keyCertSign (an absent keyUsage restricts
     * nothing).
     *
     * The mirror image of {@see isCertificateAuthority()}: here an extension we
     * cannot read fails CLOSED, because an unreadable constraint is never a
     * licence to issue.
     */
    public function mayIssueCertificates(Certificate $certificate): bool
    {
        try {
            if (! $this->assertsCa($certificate) || ! $this->keyUsagePermitsCertificateSigning($certificate)) {
                return false;
            }

            // A malformed (e.g. negative) pathLenConstraint is an unreadable
            // constraint like any other.
            $this->readPathLengthConstraint($certificate);

            return true;
        } catch (MalformedDerException) {
            return false;
        }
    }

    /**
     * The basicConstraints pathLenConstraint — how many intermediate
     * certificates may follow this CA in a path — or null when it sets none.
     * A value wider than 64 bits is no constraint in practice, so it reads as
     * none. Unreadable reads as 0: an unknowable limit admits nothing.
     */
    public function pathLengthConstraint(Certificate $certificate): ?int
    {
        try {
            $limit = $this->readPathLengthConstraint($certificate);
        } catch (MalformedDerException) {
            return 0;
        }

        return $limit === -1 ? null : $limit;
    }

    /**
     * @throws MalformedDerException
     */
    private function assertsCa(Certificate $certificate): bool
    {
        $extension = $certificate->extension(self::BASIC_CONSTRAINTS_OID);

        if ($extension === null) {
            return false;
        }

        foreach ($this->decoder->decode($extension->der)->children() as $child) {
            if ($child->class === TagClass::Universal && $child->tag === 1) {
                return $child->boolean();
            }
        }

        return false;
    }

    /**
     * `KeyUsage ::= BIT STRING` — the first content octet counts the unused
     * trailing bits, and keyCertSign is bit 5 (`0x04` of the first data octet).
     *
     * @throws MalformedDerException
     */
    private function keyUsagePermitsCertificateSigning(Certificate $certificate): bool
    {
        $extension = $certificate->extension(self::KEY_USAGE_OID);

        if ($extension === null) {
            return true;
        }

        $bits = $this->decoder->decode($extension->der);

        if ($bits->class !== TagClass::Universal || $bits->tag !== 3 || $bits->constructed || $bits->contents === '') {
            throw MalformedDerException::malformedContents('the keyUsage extension', 'it is not a BIT STRING');
        }

        if (ord($bits->contents[0]) > 7) {
            throw MalformedDerException::malformedContents('the keyUsage extension', 'it claims more than 7 unused bits');
        }

        return strlen($bits->contents) > 1 && (ord($bits->contents[1]) & 0x04) !== 0;
    }

    /**
     * The pathLenConstraint, or -1 when there is none.
     *
     * @throws MalformedDerException
     */
    private function readPathLengthConstraint(Certificate $certificate): int
    {
        $extension = $certificate->extension(self::BASIC_CONSTRAINTS_OID);

        if ($extension === null) {
            return -1;
        }

        foreach ($this->decoder->decode($extension->der)->children() as $child) {
            if ($child->class !== TagClass::Universal || $child->tag !== 2) {
                continue;
            }

            $limit = $child->integer();

            // Wider than 64 bits: its raw two's-complement bytes. Positive is
            // unbounded in practice; negative is a malformed constraint.
            if (is_string($limit)) {
                if ((ord($limit[0]) & 0x80) !== 0) {
                    throw MalformedDerException::malformedContents('the basicConstraints extension', 'its pathLenConstraint is negative');
                }

                return -1;
            }

            if ($limit < 0) {
                throw MalformedDerException::malformedContents('the basicConstraints extension', 'its pathLenConstraint is negative');
            }

            return $limit;
        }

        return -1;
    }

    /**
     * The raw AAGUID bytes the attestation certificate binds itself to, or null
     * when it carries no such extension (the extension is optional). The spec
     * requires an `OCTET STRING` — its LENGTH is the caller's to rule on.
     *
     * @throws MalformedDerException when the extension is not an `OCTET STRING`
     */
    public function fidoAaguid(Certificate $certificate): ?string
    {
        $extension = $certificate->extension(self::FIDO_AAGUID_OID);

        if ($extension === null) {
            return null;
        }

        return $this->decoder->decode($extension->der)->octetString();
    }

    /**
     * Whether the id-fido-gen-ce-aaguid extension is (illegally) marked critical.
     * WebAuthn §8.2.1: it "MUST NOT be marked as critical".
     */
    public function fidoAaguidIsCritical(Certificate $certificate): bool
    {
        return $certificate->extension(self::FIDO_AAGUID_OID)?->critical === true;
    }

    /**
     * The nonce Apple baked into a credential certificate, or null when the
     * certificate carries no such extension.
     *
     * WebAuthn §8.8 gives the shape as `SEQUENCE { [1] { OCTET STRING nonce } }`.
     * That nonce is what binds an Apple statement — which carries no signature of
     * its own — to ONE ceremony: it is `SHA-256(authenticatorData ‖
     * clientDataHash)`, and Apple's CA only ever issues a certificate over the
     * nonce the authenticator presented. Replaying a genuine statement from
     * another ceremony changes the hash, and this is where that shows up.
     *
     * @throws MalformedDerException when the extension is not that shape
     */
    public function appleNonce(Certificate $certificate): ?string
    {
        $extension = $certificate->extension(self::APPLE_NONCE_OID);

        if ($extension === null) {
            return null;
        }

        $tagged = $this->decoder->decode($extension->der)->tagged(1);

        if ($tagged === null) {
            throw MalformedDerException::malformedContents('the Apple nonce extension', 'it carries no [1] element');
        }

        $children = $tagged->children();

        if ($children === []) {
            throw MalformedDerException::malformedContents('the Apple nonce extension', 'its [1] element is empty');
        }

        return $children[0]->octetString();
    }
}
