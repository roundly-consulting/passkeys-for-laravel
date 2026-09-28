<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use RoundlyConsulting\Crypto\X509\Certificate;
use RuntimeException;

/**
 * A throwaway PKI whose every certificate carries an EXPLICIT extension block and
 * is issued by an explicit parent — the shapes crypto's TestCertificates never
 * mints, because its intermediates are always well-formed CAs: an end-entity
 * certificate that signs another one, a CA without keyCertSign, a pathLen that the
 * chain below it exceeds.
 */
final class Pki
{
    public const string CA = "basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign";

    public const string CA_WITHOUT_KEY_USAGE = 'basicConstraints = critical,CA:TRUE';

    public const string CA_WITHOUT_CERT_SIGN = "basicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature";

    public const string CA_PATH_LENGTH_ZERO = "basicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign";

    public const string CERT_SIGN_WITHOUT_BASIC_CONSTRAINTS = 'keyUsage = critical,keyCertSign';

    /** An ordinary end entity — a device identity, a client certificate. */
    public const string END_ENTITY = "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = clientAuth";

    /** A WebAuthn §8.2.1 packed attestation certificate. */
    public const string ATTESTATION = 'basicConstraints = critical,CA:FALSE';

    private function __construct(
        private readonly OpenSSLCertificate $certificate,
        private readonly OpenSSLAsymmetricKey $key,
    ) {}

    public static function root(string $extensions = self::CA, string $commonName = 'Org Root CA'): self
    {
        return self::mint($commonName, $extensions, null);
    }

    public function issue(string $commonName, string $extensions): self
    {
        return self::mint($commonName, $extensions, $this);
    }

    /** A packed attestation leaf (OU "Authenticator Attestation") issued by this certificate. */
    public function issueAttestationLeaf(): self
    {
        return self::mint('Passkeys Test Attestation Leaf', self::ATTESTATION, $this, PackedVectors::ATTESTATION_OU);
    }

    public function der(): string
    {
        return $this->certificate()->der();
    }

    public function certificate(): Certificate
    {
        $pem = '';
        openssl_x509_export($this->certificate, $pem);

        return Certificate::fromPem($pem);
    }

    /** Write this certificate out as a PEM file, e.g. a configured trust anchor. */
    public function writePem(): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'passkeys-pki-').'.pem';

        file_put_contents($path, $this->certificate()->pem());

        return $path;
    }

    public function sign(string $data): string
    {
        $signature = '';

        if (! openssl_sign($data, $signature, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Unable to sign with the test PKI key.');
        }

        return $signature;
    }

    private static function mint(string $commonName, string $extensions, ?self $issuer, ?string $organizationalUnit = null): self
    {
        $key = TestKeys::ec();
        $config = (string) tempnam(sys_get_temp_dir(), 'passkeys-pki-cnf-');

        file_put_contents($config, "[ req ]\ndistinguished_name = dn\nprompt = no\n\n[ dn ]\n\n[ v3 ]\n{$extensions}\n");

        try {
            $arguments = ['config' => $config, 'digest_alg' => 'sha256', 'x509_extensions' => 'v3'];

            $subject = ['countryName' => 'SK', 'organizationName' => 'Passkeys Test', 'commonName' => $commonName];

            if ($organizationalUnit !== null) {
                $subject['organizationalUnitName'] = $organizationalUnit;
            }

            $csr = @openssl_csr_new($subject, $key, $arguments);

            if (! $csr instanceof OpenSSLCertificateSigningRequest) {
                throw new RuntimeException('Unable to mint the test PKI request.');
            }

            $certificate = @openssl_csr_sign(
                $csr,
                $issuer?->certificate,
                $issuer?->key ?? $key,
                365,
                $arguments,
                random_int(1, PHP_INT_MAX),
            );

            if (! $certificate instanceof OpenSSLCertificate) {
                throw new RuntimeException('Unable to sign the test PKI certificate.');
            }

            return new self($certificate, $key);
        } finally {
            @unlink($config);
        }
    }
}
