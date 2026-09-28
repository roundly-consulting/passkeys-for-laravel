<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Passkeys\Events\PasskeyRevoked;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Revokes (soft-deletes) a stored credential so it can no longer authenticate,
 * and fires `PasskeyRevoked`. Unscoped: `Passkeys::for($user)` checks ownership
 * before it gets here.
 */
final readonly class RevokePasskeyAction
{
    public function __construct(
        private Dispatcher $events,
    ) {}

    public function execute(Passkey $passkey): void
    {
        $passkey->delete();

        $this->events->dispatch(new PasskeyRevoked($passkey));
    }
}
