<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use RoundlyConsulting\Crypto\Codec\Hex;

/**
 * The authenticator model identifier carried in authenticator data: 16 raw bytes
 * on the wire, a lowercase formatted UUID at rest and in policy.
 *
 * All-zero means "the authenticator declined to identify itself" (what every
 * `none`-conveyance platform authenticator sends) and is reported as null — an
 * absence, never a model whose id happens to be zero.
 */
final class Aaguid
{
    public static function format(?string $raw): ?string
    {
        if ($raw === null || strlen($raw) !== 16 || $raw === str_repeat("\x00", 16)) {
            return null;
        }

        $hex = Hex::encode($raw);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12),
        );
    }
}
