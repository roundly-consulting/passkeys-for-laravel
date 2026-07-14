<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * A host's own credential model, as `passkeys.model` documents. Exists to prove the seam
 * is honoured at every call site — a ceremony must hand this class back, and the model
 * events a host hangs revocation/audit logic on must fire for it.
 */
final class CustomPasskey extends Passkey
{
    public static int $created = 0;

    public function revoked(): bool
    {
        return $this->trashed();
    }

    protected static function booted(): void
    {
        self::created(static function (): void {
            self::$created++;
        });
    }
}
