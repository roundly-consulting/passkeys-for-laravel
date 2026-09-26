<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use Closure;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Testing\TestCertificateChain;
use RoundlyConsulting\Crypto\Testing\TestCertificates;
use RoundlyConsulting\Crypto\Testing\TestLeafOptions;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Passkeys\Testing\CborEncoder;

/**
 * Mints GENUINE `apple` attestation statements (WebAuthn §8.8) — the fixture side
 * of the Apple suite.
 *
 * Apple's shape, reproduced faithfully:
 *  - the credential certificate certifies the CREDENTIAL key itself, so the chain
 *    is minted over the very key the vector registers;
 *  - the credential certificate carries a nonce extension holding
 *    `SHA-256(authData ‖ clientDataHash)`, which is only knowable once the
 *    ceremony's bytes exist — hence the chain is minted inside the attStmt
 *    factory, exactly as Apple's CA issues it after the fact;
 *  - the statement carries x5c and NOTHING else — no sig, no alg;
 *  - the ROOT is omitted from x5c (Apple always omits it), so the anchor store
 *    has to complete the chain.
 */
final class AppleVectors
{
    public const string NONCE_OID = '1.2.840.113635.100.8.2';

    /**
     * The nonce extension's DER: `SEQUENCE { [1] { OCTET STRING nonce } }`.
     */
    public static function nonceExtension(string $nonce): string
    {
        $octetString = "\x04".chr(strlen($nonce)).$nonce;
        $tagged = "\xA1".chr(strlen($octetString)).$octetString;

        return "\x30".chr(strlen($tagged)).$tagged;
    }

    /**
     * A credential certificate for $credentialKey, carrying $nonce, under a
     * three-certificate path (credCert → intermediate → root) — Apple's shape.
     */
    public static function chain(
        string $nonce,
        EcKey $credentialKey,
        int $length = 3,
        int $days = 365,
        bool $withNonce = true,
    ): TestCertificateChain {
        $extensions = $withNonce ? [self::NONCE_OID => self::nonceExtension($nonce)] : [];

        return TestCertificates::chain(
            length: $length,
            commonName: 'Apple WebAuthn Test Credential',
            days: $days,
            leafOptions: new TestLeafOptions(rawExtensions: $extensions),
            leafKey: $credentialKey,
        );
    }

    /**
     * The attStmt factory for a genuine Apple statement. The chain is minted from
     * the ceremony's own bytes and handed back through $chain, so a test can point
     * its anchors at the root the statement actually chains to.
     *
     * The nonce is only knowable once the ceremony's bytes exist, so the chain
     * cannot be minted before the ceremony runs — which means its root cannot be
     * configured as an anchor beforehand either. `$writeRootTo` closes that: the
     * root is written to a path the host already points `attestation_anchors` at,
     * and the anchor store (which loads lazily, at verification) picks it up.
     *
     * @param  Closure(string, string): string|null  $tamper  rewrites the nonce's inputs (authData, clientDataHash)
     */
    public static function statement(
        EcKey $credentialKey,
        ?TestCertificateChain &$chain = null,
        bool $withNonce = true,
        bool $omitRoot = true,
        int $length = 3,
        ?Closure $tamper = null,
        ?string $writeRootTo = null,
    ): Closure {
        return static function (string $authData, string $clientDataHash) use (
            $credentialKey,
            &$chain,
            $withNonce,
            $omitRoot,
            $length,
            $tamper,
            $writeRootTo,
        ): string {
            $nonced = $tamper === null
                ? $authData.$clientDataHash
                : $tamper($authData, $clientDataHash);

            $chain = self::chain(
                nonce: hash('sha256', $nonced, true),
                credentialKey: $credentialKey,
                length: $length,
                withNonce: $withNonce,
            );

            if ($writeRootTo !== null) {
                file_put_contents($writeRootTo, $chain->root()->pem());
            }

            return self::attStmt(self::x5c($chain, $omitRoot));
        };
    }

    /**
     * The Apple attStmt: an x5c and nothing else.
     *
     * @param  list<string>  $x5c  raw DER certificates, credCert first
     */
    public static function attStmt(array $x5c): string
    {
        return CborEncoder::map([[
            CborEncoder::tstr('x5c'),
            CborEncoder::arr(array_map(static fn (string $der): string => CborEncoder::bstr($der), $x5c)),
        ]]);
    }

    /**
     * The chain as RAW DER, root omitted by default — what Apple actually sends.
     *
     * @return list<string>
     */
    public static function x5c(TestCertificateChain $chain, bool $omitRoot = true): array
    {
        $certificates = $chain->chain->certificates();

        if ($omitRoot && count($certificates) > 1) {
            array_pop($certificates);
        }

        return array_values(array_map(
            static fn (Certificate $certificate): string => $certificate->der(),
            $certificates,
        ));
    }
}
