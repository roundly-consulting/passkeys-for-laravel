<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Support;

use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Testing\Fixtures\Concerns\CountsCreations;

/**
 * A host's own credential model, as `passkeys.model` documents. Exists to prove the seam
 * is honoured at every call site — a ceremony must hand this class back, and the model
 * events a host hangs revocation/audit logic on must fire for it.
 */
final class CustomPasskey extends Passkey
{
    /**
     * Replaces a hand-rolled `public static int $created` + a booted() hook that counted the
     * same thing. Counting `created` events on this exact class is the independent oracle a
     * swap really took effect — `instanceof` passes for a row created as the PACKAGED class,
     * which never fires the events a host hangs revocation/audit logic on. Without this trait
     * `toHonourModelSwap` silently downgrades to that weaker check.
     */
    use CountsCreations;

    public function revoked(): bool
    {
        return $this->trashed();
    }
}
