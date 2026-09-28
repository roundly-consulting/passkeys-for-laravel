<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Facades\Passkeys;

/*
 * The facade contract, pinned: the docblock matches the PasskeyService contract (the root) and
 * the accessor is its class-string; fake() is real, a PasskeyService subtype, and takes over DI
 * too; and all six actions under src/Actions are reachable — the discoverable ceremony flat on
 * the manager, everything account-scoped through `Passkeys::for($user)`.
 */
it('keeps the facade complete, fakeable and covering every action', function (): void {
    expect(Passkeys::class)
        ->toDocumentItsRoot()
        ->toBeFakeable()
        ->toReachEveryAction(__DIR__.'/../../src/Actions');
});
