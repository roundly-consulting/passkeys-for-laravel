<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\CustomPasskey;
use RoundlyConsulting\Passkeys\Tests\Support\User;

/**
 * The model-swap proof (S) for the `passkeys.model` seam, with the swap applied BEFORE the
 * providers boot — which is what a real host does, and what the existing
 * `ConfiguredModelTest` (a body-time swap) cannot exercise.
 *
 * The bugs this class of test exists for:
 *  - a runtime `config()->set()` leaves whatever the provider hung at boot on the packaged
 *    class (media #28);
 *  - `instanceof` passes for a row created as the packaged class — which never fires the
 *    host's model events (permissions #31). {@see CountsCreations} on the fixture is the
 *    independent oracle; without it this assertion silently downgrades.
 *
 * The exercise deliberately uses the factory and the user relation rather than a full
 * WebAuthn ceremony: the ceremony path's swap behaviour is already asserted by
 * ConfiguredModelTest, and this case's question is whether a BEFORE-BOOT swap survives — a
 * question the persistence path answers without depending on EC key generation.
 */
it('honours a host credential model swapped in before boot', function (): void {
    expect('passkeys.model')->toHonourModelSwap(CustomPasskey::class, function (): array {
        $user = User::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);

        $passkey = Passkey::factory()->es256()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id' => $user->getKey(),
        ]);

        return [
            $passkey,
            // The relation the host reads credentials back through must hydrate its class.
            ...$user->passkeys()->get()->all(),
        ];
    });
});
