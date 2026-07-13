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

    /** WebAuthn §8.2.1 — id-fido-gen-ce-aaguid. */
    public const string FIDO_AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

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
        $extension = $certificate->extension(self::BASIC_CONSTRAINTS_OID);

        if ($extension === null) {
            return false;
        }

        try {
            foreach ($this->decoder->decode($extension->der)->children() as $child) {
                if ($child->class === TagClass::Universal && $child->tag === 1) {
                    return $child->boolean();
                }
            }
        } catch (MalformedDerException) {
            // A basicConstraints extension we cannot read is not a licence to
            // treat the certificate as an end entity.
            return true;
        }

        return false;
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
}
