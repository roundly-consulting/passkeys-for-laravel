<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Cose\AuthenticatorData;
use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Crypto\Cose\CoseAlgorithm;
use RoundlyConsulting\Crypto\Cose\CoseKey;
use RoundlyConsulting\Crypto\Cose\MalformedCborException;
use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\Signature\Key\PublicKey;
use RoundlyConsulting\Crypto\Signature\KeyVerifier;
use RoundlyConsulting\Passkeys\DataTransferObjects\AttestationObject;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidCoseKey;
use RoundlyConsulting\Passkeys\Exceptions\MalformedCbor;
use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Exceptions\SignatureInvalid;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAlgorithm;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * The single boundary between the WebAuthn ceremony and crypto-for-laravel.
 *
 * Every CBOR decode, COSE key parse and signature check the relying party makes
 * runs through crypto's audited primitives here, and every CryptoException is
 * translated into this package's own typed exception, so callers keep catching
 * exactly what they always did. No algorithm is implemented in this package.
 *
 * The at-rest COSE public key stays standard (padded) base64: {@see Base64} is
 * byte-for-byte the base64_encode/base64_decode pair it replaced, so credentials
 * registered before this package built on crypto keep authenticating unchanged.
 */
final readonly class CredentialCrypto
{
    public function __construct(
        private CborDecoder $cbor,
        private KeyVerifier $verifier,
    ) {}

    /**
     * CBOR-decode a registration response's attestationObject (trailing-byte strict).
     *
     * @throws MalformedCbor|InvalidClientData
     */
    public function attestationObject(string $bytes): AttestationObject
    {
        try {
            $decoded = $this->cbor->decode($bytes);
        } catch (MalformedCborException $e) {
            throw MalformedCbor::make($e->getMessage());
        }

        return AttestationObject::fromDecoded($decoded);
    }

    /**
     * Parse the authenticatorData byte structure (WebAuthn §6.1), including the
     * attested COSE credential key when the AT flag is set.
     *
     * @throws PasskeyException
     */
    public function authenticatorData(string $bytes): AuthenticatorData
    {
        try {
            return AuthenticatorData::parse($bytes);
        } catch (CryptoException $e) {
            throw self::translate($e, InvalidAuthenticatorData::because($e->getMessage()));
        }
    }

    /**
     * Rebuild the verification key from a stored credential's at-rest COSE bytes.
     *
     * @throws PasskeyException
     */
    public function storedPublicKey(Passkey $passkey): PublicKey
    {
        try {
            $coseBytes = Base64::decode($passkey->public_key);
        } catch (InvalidEncodingException) {
            throw SignatureInvalid::make();
        }

        try {
            $decoded = $this->cbor->decode($coseBytes);
        } catch (MalformedCborException $e) {
            throw MalformedCbor::make($e->getMessage());
        }

        if (! is_array($decoded)) {
            throw SignatureInvalid::make();
        }

        try {
            return CoseKey::fromDecoded($decoded);
        } catch (CryptoException $e) {
            throw self::translate($e, MalformedCbor::make($e->getMessage()));
        }
    }

    /**
     * Verify a signature over the signed data, pinned to the algorithm of the key
     * itself — never to anything the assertion carries. ECDSA signatures are
     * accepted in the DER form WebAuthn delivers (and in the raw r‖s form).
     *
     * @throws UnsupportedAlgorithm when the credential is EdDSA and ext-sodium is absent
     */
    public function verify(PublicKey $key, string $signedData, string $signature): bool
    {
        try {
            return $this->verifier->verify($key, $signedData, $signature);
        } catch (UnsupportedAlgorithmException $e) {
            throw UnsupportedAlgorithm::because($e->getMessage());
        } catch (CryptoException) {
            // A malformed, attacker-supplied signature is a failed verification,
            // never an error the host has to handle.
            return false;
        }
    }

    /**
     * The COSE algorithm identifier (IANA registry) a parsed key was minted for,
     * so the ceremony can hold it against the configured allow-list.
     *
     * @throws UnsupportedAlgorithm
     */
    public function coseAlgorithm(PublicKey $key): CoseAlgorithm
    {
        $algorithm = $key->algorithm();

        foreach (CoseAlgorithm::cases() as $case) {
            if ($case->toSignatureAlgorithm() === $algorithm) {
                return $case;
            }
        }

        throw UnsupportedAlgorithm::because($algorithm->value);
    }

    /**
     * Encode a COSE key for storage — standard, padded base64, unchanged from the
     * encoding every already-registered credential was written with.
     */
    public function encodePublicKey(string $coseBytes): string
    {
        return Base64::encode($coseBytes);
    }

    /**
     * Map a crypto failure onto this package's exception vocabulary.
     *
     * An unknown COSE algorithm / key type / curve is always an unsupported
     * algorithm; anything that failed while loading key material (bad coordinates,
     * a weak or oversized RSA modulus, an unusable exponent) is an invalid COSE
     * key. Everything else is the caller's structural default.
     */
    private static function translate(CryptoException $error, PasskeyException $default): PasskeyException
    {
        return match (true) {
            $error instanceof UnsupportedAlgorithmException => UnsupportedAlgorithm::because($error->getMessage()),
            $error instanceof MalformedCborException => $default,
            default => InvalidCoseKey::make($error->getMessage()),
        };
    }
}
