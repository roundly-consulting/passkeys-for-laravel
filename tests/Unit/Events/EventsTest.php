<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Events\PasskeyAuthenticated;
use RoundlyConsulting\Passkeys\Events\PasskeyRegistered;
use RoundlyConsulting\Passkeys\Events\PasskeySignCountRegressed;
use RoundlyConsulting\Passkeys\Models\Passkey;

it('carries the passkey on the registered event', function (): void {
    $passkey = Passkey::factory()->make();

    expect((new PasskeyRegistered($passkey))->passkey)->toBe($passkey);
});

it('carries the passkey on the authenticated event', function (): void {
    $passkey = Passkey::factory()->make();

    expect((new PasskeyAuthenticated($passkey))->passkey)->toBe($passkey);
});

it('carries the counters on the sign-count regression event', function (): void {
    $passkey = Passkey::factory()->make();

    $event = new PasskeySignCountRegressed($passkey, stored: 10, received: 5);

    expect($event->passkey)->toBe($passkey)
        ->and($event->stored)->toBe(10)
        ->and($event->received)->toBe(5);
});
