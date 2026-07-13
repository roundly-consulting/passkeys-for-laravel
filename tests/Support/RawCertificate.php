<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use OpenSSLAsymmetricKey;
use OpenSSLCertificateSigningRequest;
use RoundlyConsulting\Crypto\X509\Certificate;
use RuntimeException;

/**
 * A self-signed certificate minted from an EXPLICIT openssl extension block, for
 * the certificate shapes crypto's TestCertificates deliberately cannot produce:
 * a v1 certificate, a leaf asserting `CA:TRUE`, a leaf with no basicConstraints
 * at all, and a basicConstraints whose bytes are not DER.
 *
 * Each is a WebAuthn §8.2.1 requirement the verifier must refuse (or, for the
 * missing extension, accept as an end entity per RFC 5280's DEFAULT FALSE), so
 * every one of them needs a real certificate to hold the verifier against.
 */
final class RawCertificate
{
    private function __construct(
        public readonly string $der,
        private readonly OpenSSLAsymmetricKey $key,
    ) {}

    /**
     * @param  string  $extensions  the body of the certificate's `v3` section;
     *                              an empty string mints a v1 certificate
     */
    public static function mint(string $extensions = '', string $organizationalUnit = PackedVectors::ATTESTATION_OU): self
    {
        $key = TestKeys::ec();
        $config = self::writeConfig($extensions);

        try {
            $arguments = ['config' => $config, 'digest_alg' => 'sha256'];

            if ($extensions !== '') {
                $arguments['x509_extensions'] = 'v3';
            }

            $csr = @openssl_csr_new([
                'commonName' => 'Passkeys Raw Test Leaf',
                'organizationName' => 'Passkeys Test',
                'organizationalUnitName' => $organizationalUnit,
            ], $key, $arguments);

            if (! $csr instanceof OpenSSLCertificateSigningRequest) {
                throw new RuntimeException('Unable to mint the raw test certificate request.');
            }

            $certificate = @openssl_csr_sign($csr, null, $key, 365, $arguments, random_int(1, PHP_INT_MAX));

            if ($certificate === false) {
                throw new RuntimeException('Unable to sign the raw test certificate.');
            }

            $pem = '';
            openssl_x509_export($certificate, $pem);

            return new self(Certificate::fromPem($pem)->der(), $key);
        } finally {
            @unlink($config);
        }
    }

    public function sign(string $data): string
    {
        $signature = '';

        if (! openssl_sign($data, $signature, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Unable to sign with the raw test certificate key.');
        }

        return $signature;
    }

    private static function writeConfig(string $extensions): string
    {
        $config = <<<CNF
            [ req ]
            distinguished_name = dn
            prompt = no

            [ dn ]

            [ v3 ]
            {$extensions}
            CNF;

        $path = (string) tempnam(sys_get_temp_dir(), 'passkeys-raw-cert-');

        file_put_contents($path, $config);

        return $path;
    }
}
