<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation\Support;

use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Signature\Key\EcKey;
use RoundlyConsulting\Crypto\Signature\Key\OkpKey;
use RoundlyConsulting\Crypto\Signature\Key\PublicKey;
use RoundlyConsulting\Crypto\Signature\Key\RsaKey;

/**
 * Whether two public keys are the SAME key.
 *
 * Attestation formats that carry no signature over the authenticator data —
 * `apple` above all — bind the certificate to the credential by requiring the
 * certificate's subject public key to BE the credential key. Without that check
 * an attacker could present someone else's genuine certificate path alongside
 * their own credential.
 *
 * Keys are compared on their material (curve + affine point, modulus + exponent,
 * or the raw Ed25519 point), never on an encoding: two keys are equal when they
 * are the same key, whatever wrapper they arrived in. Different key TYPES are
 * never equal.
 */
final class KeysMatch
{
    public static function check(PublicKey $a, PublicKey $b): bool
    {
        return match (true) {
            $a instanceof EcKey && $b instanceof EcKey => self::ec($a, $b),
            $a instanceof RsaKey && $b instanceof RsaKey => self::rsa($a, $b),
            $a instanceof OkpKey && $b instanceof OkpKey => ConstantTime::equals($a->publicKey, $b->publicKey),
            default => false,
        };
    }

    private static function ec(EcKey $a, EcKey $b): bool
    {
        if ($a->curve !== $b->curve) {
            return false;
        }

        // Coordinates are fixed-length padded to the curve, so equal points always
        // compare byte-for-byte equal.
        return ConstantTime::equals($a->coordinates()->x, $b->coordinates()->x)
            && ConstantTime::equals($a->coordinates()->y, $b->coordinates()->y);
    }

    private static function rsa(RsaKey $a, RsaKey $b): bool
    {
        return ConstantTime::equals($a->modulus(), $b->modulus())
            && ConstantTime::equals($a->exponent(), $b->exponent());
    }
}
