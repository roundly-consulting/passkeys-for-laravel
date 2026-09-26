<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use Closure;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;
use RoundlyConsulting\Crypto\Testing\TestCertificateChain;
use RoundlyConsulting\Crypto\Testing\TestCertificates;
use RoundlyConsulting\Crypto\Testing\TestLeafOptions;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Passkeys\Testing\CborEncoder;
use RuntimeException;

/**
 * Mints GENUINE `packed` attestation statements (WebAuthn §8.2) from a throwaway
 * certificate chain — the fixture side of the attestation suite.
 *
 * The x5c entries are RAW DER, exactly as CBOR carries them. A statement built
 * from base64 (the JOSE shape) is what `base64X5c()` produces, and the verifier
 * must refuse it.
 */
final class PackedVectors
{
    public const string AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

    public const string ATTESTATION_OU = 'Authenticator Attestation';

    /**
     * A batch-attestation chain shaped like a real security key's: an OU of
     * "Authenticator Attestation" and (optionally) the id-fido-gen-ce-aaguid
     * extension binding it to one authenticator model.
     */
    public static function chain(
        ?string $aaguid = null,
        string $leafKeyType = 'EC',
        int $length = 2,
        int $days = 365,
        bool $criticalAaguid = false,
        ?string $organizationalUnit = self::ATTESTATION_OU,
    ): TestCertificateChain {
        $extensions = $aaguid === null ? [] : [self::AAGUID_OID => "\x04\x10".$aaguid];

        return TestCertificates::chain(
            length: $length,
            leafKeyType: $leafKeyType,
            commonName: 'Passkeys Test Attestation Leaf',
            days: $days,
            leafOptions: new TestLeafOptions(
                rawExtensions: $extensions,
                criticalRawExtensions: $criticalAaguid,
                subjectOrganizationalUnit: $organizationalUnit,
            ),
        );
    }

    /**
     * The attStmt factory for an x5c-chained statement, signed by the chain's
     * leaf key over `authData ‖ clientDataHash`.
     *
     * @param  list<string>|null  $x5c  raw DER entries; defaults to the whole chain
     */
    public static function chained(
        TestCertificateChain $chain,
        ?int $algorithm = null,
        ?array $x5c = null,
        bool $tamperSignature = false,
    ): Closure {
        return static function (string $authData, string $clientDataHash) use ($chain, $algorithm, $x5c, $tamperSignature): string {
            $signature = self::sign($chain->leafKey, $authData.$clientDataHash);

            if ($tamperSignature) {
                $signature[strlen($signature) - 1] = $signature[strlen($signature) - 1] === "\x00" ? "\x01" : "\x00";
            }

            return self::statement(
                $algorithm ?? self::algorithmOf($chain->leafKey),
                $signature,
                $x5c ?? self::x5c($chain),
            );
        };
    }

    /**
     * The attStmt factory for a SELF-attested statement: no x5c, signed by the
     * credential key itself.
     */
    public static function selfAttested(WebAuthnVectors $vectors, ?int $algorithm = null, bool $tamperSignature = false): Closure
    {
        return static function (string $authData, string $clientDataHash) use ($vectors, $algorithm, $tamperSignature): string {
            $signature = $vectors->signWithCredentialKey($authData.$clientDataHash);

            if ($tamperSignature) {
                $signature[strlen($signature) - 1] = $signature[strlen($signature) - 1] === "\x00" ? "\x01" : "\x00";
            }

            return self::statement($algorithm ?? $vectors->coseAlgorithm(), $signature, []);
        };
    }

    /**
     * @param  list<string>  $x5c  raw DER certificates, leaf first
     */
    public static function statement(int $algorithm, string $signature, array $x5c): string
    {
        $pairs = [
            [CborEncoder::tstr('alg'), CborEncoder::nint($algorithm)],
            [CborEncoder::tstr('sig'), CborEncoder::bstr($signature)],
        ];

        if ($x5c !== []) {
            $pairs[] = [
                CborEncoder::tstr('x5c'),
                CborEncoder::arr(array_map(static fn (string $der): string => CborEncoder::bstr($der), $x5c)),
            ];
        }

        return CborEncoder::map($pairs);
    }

    /**
     * The chain as RAW DER — what a real authenticator sends.
     *
     * @return list<string>
     */
    public static function x5c(TestCertificateChain $chain): array
    {
        return array_map(
            static fn (Certificate $certificate): string => $certificate->der(),
            $chain->chain->certificates(),
        );
    }

    /**
     * The chain as BASE64 — the JOSE shape, which CBOR never carries. Feeding
     * these to the verifier must fail loudly.
     *
     * @return list<string>
     */
    public static function base64X5c(TestCertificateChain $chain): array
    {
        return array_map(
            static fn (Certificate $certificate): string => $certificate->base64(),
            $chain->chain->certificates(),
        );
    }

    public static function sign(EcKey|RsaKey $key, string $data): string
    {
        $signature = '';

        if (! openssl_sign($data, $signature, $key->key, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Unable to sign the attestation statement.');
        }

        return $signature;
    }

    public static function algorithmOf(EcKey|RsaKey $key): int
    {
        return $key instanceof RsaKey ? -257 : -7;
    }
}
