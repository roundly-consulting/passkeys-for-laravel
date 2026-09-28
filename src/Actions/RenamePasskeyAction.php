<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Passkeys\Events\PasskeyRenamed;
use RoundlyConsulting\Passkeys\Models\Passkey;

/**
 * Renames a stored credential — cosmetic only, never a verification input — and
 * fires `PasskeyRenamed` with the previous name. Unscoped: `Passkeys::for($user)`
 * checks ownership before it gets here.
 */
final readonly class RenamePasskeyAction
{
    public function __construct(
        private Dispatcher $events,
    ) {}

    public function execute(Passkey $passkey, string $name): Passkey
    {
        $previousName = $passkey->name;

        $passkey->forceFill(['name' => $name])->save();

        $this->events->dispatch(new PasskeyRenamed($passkey, $previousName));

        return $passkey;
    }
}
