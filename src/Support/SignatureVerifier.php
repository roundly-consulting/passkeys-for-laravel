<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use RoundlyConsulting\Passkeys\DataTransferObjects\CoseKeyData;
use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Exceptions\UnsupportedAlgorithm;

/**
 * Verifies a signature over the signed data using a parsed COSE key. Returns a
 * plain bool; callers translate a false into the appropriate typed exception.
 */
final class SignatureVerifier
{
    public function verify(CoseKeyData $key, string $data, string $signature): bool
    {
        return match ($key->algorithm) {
            CoseAlgorithm::ES256 => $this->verifyEcdsa($key, $data, $signature),
            CoseAlgorithm::RS256 => $this->verifyOpenssl($key, $data, $signature),
            CoseAlgorithm::EdDSA => $this->verifyEd25519($key, $data, $signature),
        };
    }

    private function verifyEcdsa(CoseKeyData $key, string $data, string $signature): bool
    {
        // WebAuthn delivers ECDSA signatures in DER, but normalise a raw r‖s form
        // defensively. Reject anything that is neither valid DER nor a 64-byte pair.
        if (Asn1::isValidEcdsaDer($signature)) {
            $der = $signature;
        } elseif (strlen($signature) === 64) {
            $der = Asn1::ecdsaRawToDer($signature);
        } else {
            return false;
        }

        return $this->verifyOpenssl($key, $data, $der);
    }

    private function verifyOpenssl(CoseKeyData $key, string $data, string $signature): bool
    {
        if ($key->pem === null) {
            return false;
        }

        // The signature is attacker-controlled, so a malformed key/signature must
        // fail quietly rather than surface a PHP warning. openssl_verify returns
        // 1 (valid), 0 (invalid) or -1 (error) — only an exact 1 is a pass.
        return @openssl_verify($data, $signature, $key->pem, $key->algorithm->opensslAlgorithm()) === 1;
    }

    private function verifyEd25519(CoseKeyData $key, string $data, string $signature): bool
    {
        if (! function_exists('sodium_crypto_sign_verify_detached')) {
            throw UnsupportedAlgorithm::forId(CoseAlgorithm::EdDSA->value);
        }

        if ($key->edwardsPublicKey === null || $key->edwardsPublicKey === '' || strlen($signature) !== 64) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $data, $key->edwardsPublicKey);
    }
}
