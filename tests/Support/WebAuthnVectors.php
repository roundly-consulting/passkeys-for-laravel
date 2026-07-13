<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use OpenSSLAsymmetricKey;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RuntimeException;

/**
 * Synthesizes cryptographically valid WebAuthn ceremony payloads for tests, from
 * a freshly generated ES256, RS256, or EdDSA (Ed25519) key pair. Standards-based
 * (WebAuthn/FIDO2) — no third-party or dev WebAuthn library is used to build or
 * verify vectors.
 *
 * ES256 assertions are signed into ASN.1 DER, which is the form authenticators
 * actually deliver; EdDSA is signed with ext-sodium into a raw 64-byte signature.
 */
final class WebAuthnVectors
{
    public const RP_ID = 'example.com';

    public const ORIGIN = 'https://example.com';

    private function __construct(
        private readonly OpenSSLAsymmetricKey|string $privateKey,
        private readonly string $coseKey,
        private readonly string $credentialId,
        private readonly int $coseAlgorithm,
    ) {}

    public static function es256(): self
    {
        $key = TestKeys::ec();

        $details = self::details($key);
        $x = str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);

        $cose = CborEncoder::map([
            [CborEncoder::uint(1), CborEncoder::uint(2)],   // kty: EC2
            [CborEncoder::uint(3), CborEncoder::nint(-7)],  // alg: ES256
            [CborEncoder::nint(-1), CborEncoder::uint(1)],  // crv: P-256
            [CborEncoder::nint(-2), CborEncoder::bstr($x)],
            [CborEncoder::nint(-3), CborEncoder::bstr($y)],
        ]);

        return new self($key, $cose, random_bytes(20), -7);
    }

    public static function rs256(): self
    {
        $key = TestKeys::rsa();

        $details = self::details($key);

        $cose = CborEncoder::map([
            [CborEncoder::uint(1), CborEncoder::uint(3)],      // kty: RSA
            [CborEncoder::uint(3), CborEncoder::nint(-257)],   // alg: RS256
            [CborEncoder::nint(-1), CborEncoder::bstr($details['rsa']['n'])],
            [CborEncoder::nint(-2), CborEncoder::bstr($details['rsa']['e'])],
        ]);

        return new self($key, $cose, random_bytes(20), -257);
    }

    public static function eddsa(): self
    {
        $keypair = sodium_crypto_sign_keypair();

        $cose = CborEncoder::map([
            [CborEncoder::uint(1), CborEncoder::uint(1)],      // kty: OKP
            [CborEncoder::uint(3), CborEncoder::nint(-8)],     // alg: EdDSA
            [CborEncoder::nint(-1), CborEncoder::uint(6)],     // crv: Ed25519
            [CborEncoder::nint(-2), CborEncoder::bstr(sodium_crypto_sign_publickey($keypair))],
        ]);

        return new self(sodium_crypto_sign_secretkey($keypair), $cose, random_bytes(20), -8);
    }

    public function credentialId(): string
    {
        return $this->credentialId;
    }

    public function coseAlgorithm(): int
    {
        return $this->coseAlgorithm;
    }

    /**
     * Rebuild the vector around an explicit credential id (e.g. a long roaming
     * security-key id), keeping the same key pair.
     */
    public function withCredentialId(string $credentialId): self
    {
        return new self($this->privateKey, $this->coseKey, $credentialId, $this->coseAlgorithm);
    }

    public function coseKey(): string
    {
        return $this->coseKey;
    }

    /**
     * The COSE key exactly as this package stores it at rest: standard, padded
     * base64 — the encoding every already-registered credential carries.
     */
    public function storedPublicKey(): string
    {
        return base64_encode($this->coseKey);
    }

    /**
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     */
    public function registrationResponse(array $options = []): array
    {
        $challenge = self::string($options, 'challenge', Base64Url::encode(random_bytes(32)));
        $rpId = self::string($options, 'rpId', self::RP_ID);
        $flags = self::int($options, 'flags', 0x45); // UP | UV | AT
        $signCount = self::int($options, 'signCount', 0);
        $aaguid = self::string($options, 'aaguid', str_repeat("\x11", 16));

        // An authenticator that does not set the AT flag sends no attested
        // credential data either, so the structure stays self-consistent.
        $attested = ($flags & 0x40) === 0 ? '' : $this->attestedCredentialData($aaguid);

        $authData = $this->authData($rpId, $flags, $signCount, $attested);

        $clientData = $this->clientDataJson(self::string($options, 'type', 'webauthn.create'), $challenge, $options);

        // `attStmt` is handed in already CBOR-encoded so a fixture can carry a
        // bogus statement of any shape; `attStmtFactory` gets the very bytes an
        // attestation signature is made over — authData ‖ SHA-256(clientDataJSON).
        $factory = $options['attStmtFactory'] ?? null;

        $statement = match (true) {
            is_callable($factory) => (string) $factory($authData, hash('sha256', $clientData, true)),
            is_string($options['attStmt'] ?? null) => $options['attStmt'],
            default => CborEncoder::map([]),
        };

        $attestationObject = CborEncoder::map([
            [CborEncoder::tstr('fmt'), CborEncoder::tstr(self::string($options, 'fmt', 'none'))],
            [CborEncoder::tstr('attStmt'), $statement],
            [CborEncoder::tstr('authData'), CborEncoder::bstr($authData)],
        ]);

        return [
            'id' => Base64Url::encode($this->credentialId),
            'rawId' => Base64Url::encode($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64Url::encode($clientData),
                'attestationObject' => Base64Url::encode($attestationObject),
                'transports' => ['internal', 'hybrid'],
            ],
            'ceremonyId' => self::string($options, 'ceremonyId', 'ceremony'),
        ];
    }

    /**
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     */
    public function assertionResponse(array $options = []): array
    {
        $challenge = self::string($options, 'challenge', Base64Url::encode(random_bytes(32)));
        $rpId = self::string($options, 'rpId', self::RP_ID);
        $flags = self::int($options, 'flags', 0x05); // UP | UV
        $signCount = self::int($options, 'signCount', 1);

        $authData = $this->authData($rpId, $flags, $signCount, '');
        $clientData = $this->clientDataJson(self::string($options, 'type', 'webauthn.get'), $challenge, $options);
        $signedData = $authData.hash('sha256', $clientData, true);

        if (($options['tamperSignedData'] ?? false) === true) {
            $signedData = $authData."\x00".hash('sha256', $clientData, true);
        }

        $signature = $this->sign($signedData);

        if (($options['tamperSignature'] ?? false) === true) {
            $signature = self::tamper($signature);
        }

        $userHandle = $options['userHandle'] ?? null;

        return [
            'id' => Base64Url::encode($this->credentialId),
            'rawId' => Base64Url::encode($this->credentialId),
            'type' => 'public-key',
            'response' => array_filter([
                'clientDataJSON' => Base64Url::encode($clientData),
                'authenticatorData' => Base64Url::encode($authData),
                'signature' => Base64Url::encode($signature),
                'userHandle' => is_string($userHandle) ? Base64Url::encode($userHandle) : null,
            ], static fn (mixed $value): bool => $value !== null),
            'ceremonyId' => self::string($options, 'ceremonyId', 'ceremony'),
        ];
    }

    /**
     * Sign with the CREDENTIAL's own key — what a self-attested `packed`
     * statement is signed with.
     */
    public function signWithCredentialKey(string $data): string
    {
        return $this->sign($data);
    }

    /**
     * ES256/RS256 sign through OpenSSL (ES256 comes out as ASN.1 DER, exactly as
     * a real authenticator delivers it); EdDSA signs a raw 64-byte value.
     */
    private function sign(string $signedData): string
    {
        if (is_string($this->privateKey)) {
            return sodium_crypto_sign_detached($signedData, $this->privateKey);
        }

        $signature = '';
        openssl_sign($signedData, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);

        return $signature;
    }

    /**
     * Flip a byte inside the signature value. For an ES256 DER signature the last
     * byte belongs to `s`, so the structure stays well-formed and only the maths
     * fails — which is what a real tampering attempt looks like.
     */
    private static function tamper(string $signature): string
    {
        $last = strlen($signature) - 1;
        $signature[$last] = $signature[$last] === "\x00" ? "\x01" : "\x00";

        return $signature;
    }

    private function attestedCredentialData(string $aaguid): string
    {
        return $aaguid.pack('n', strlen($this->credentialId)).$this->credentialId.$this->coseKey;
    }

    private function authData(string $rpId, int $flags, int $signCount, string $attested): string
    {
        return hash('sha256', $rpId, true).chr($flags).pack('N', $signCount).$attested;
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private function clientDataJson(string $type, string $challenge, array $options): string
    {
        $data = [
            'type' => $type,
            'challenge' => $challenge,
            'origin' => self::string($options, 'origin', self::ORIGIN),
            'crossOrigin' => (bool) ($options['crossOrigin'] ?? false),
        ];

        return (string) json_encode($data);
    }

    /**
     * @return array{ec?: array{x: string, y: string}, rsa?: array{n: string, e: string}}
     */
    private static function details(OpenSSLAsymmetricKey $key): array
    {
        $details = openssl_pkey_get_details($key);

        if ($details === false) {
            throw new RuntimeException('Unable to read key details.');
        }

        /** @var array{ec?: array{x: string, y: string}, rsa?: array{n: string, e: string}} $details */
        return $details;
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private static function string(array $options, string $key, string $default): string
    {
        return is_string($options[$key] ?? null) ? $options[$key] : $default;
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private static function int(array $options, string $key, int $default): int
    {
        return is_int($options[$key] ?? null) ? $options[$key] : $default;
    }
}
