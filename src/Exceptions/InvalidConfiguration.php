<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

final class InvalidConfiguration extends PasskeyException
{
    public static function missingRpId(): self
    {
        return new self(self::trans('missing_rp_id'));
    }

    public static function emptyOrigins(): self
    {
        return new self(self::trans('empty_origins'));
    }

    public static function unsupportedAlgorithm(int $alg): self
    {
        return new self(self::trans('unsupported_configured_algorithm', ['alg' => (string) $alg]));
    }

    /**
     * The host demands attestation proof while telling authenticators not to send
     * any — every registration would fail, mysteriously, at the gate.
     */
    public static function attestationConveyanceMismatch(string $trust): self
    {
        return new self(self::trans('attestation_conveyance_mismatch', ['trust' => $trust]));
    }

    /**
     * A typo'd clock skew is a configuration bug, never a forged registration —
     * so it is an InvalidConfiguration, not something catchable as an attestation
     * failure.
     */
    public static function invalidClockSkew(string $value, int $max): self
    {
        return new self(self::trans('attestation_invalid_clock_skew', [
            'seconds' => $value,
            'max' => (string) $max,
        ]));
    }

    public static function unreadableAttestationAnchor(string $format, string $path): self
    {
        return new self(self::trans('attestation_unreadable_anchor', [
            'format' => $format,
            'path' => $path,
        ]));
    }

    /**
     * A configured value of the wrong shape, named by its key under `passkeys.` — a
     * typo fails loudly instead of reading as the default.
     */
    public static function invalidValue(string $key, string $expected, mixed $given): self
    {
        return new self(self::trans('invalid_config_value', [
            'key' => $key,
            'expected' => $expected,
            'given' => is_string($given) ? '"'.$given.'"' : get_debug_type($given),
        ]));
    }
}
