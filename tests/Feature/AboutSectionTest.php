<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;

/**
 * `php artisan about` must describe the relying party without ever leaking its credential
 * surface: the RP ID, the origin allow-list, the trust-anchor paths and the AAGUID
 * allow-list are reported by posture, presence and count — never by value.
 */
it('reports the relying party posture in the about command', function (): void {
    Artisan::call('about', ['--only' => 'passkeys']);

    $rendered = Artisan::output();

    expect($rendered)->toContain('Attestation')
        ->and($rendered)->toContain('trust ignore')
        ->and($rendered)->toContain('Sign-count policy')
        ->and($rendered)->toContain('2 algorithm(s)');
});

it('never renders the rp id, origins, anchor paths or allowed aaguids', function (): void {
    config()->set('passkeys.rp.id', 'auth.acme-internal.example');
    config()->set('passkeys.rp.name', 'ACME Internal SSO');
    config()->set('passkeys.origins', ['https://auth.acme-internal.example', 'https://admin.acme-internal.example']);
    config()->set('passkeys.challenge.store', 'acme-tenant-redis');
    config()->set('passkeys.user.handle_column', 'acme_webauthn_handle');
    config()->set('passkeys.attestation_anchors.paths', [
        'packed' => ['/srv/acme/secrets/yubico-ca.pem'],
    ]);
    config()->set('passkeys.aaguids.allowed', [
        'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4',
        'd8522d9f-575b-4866-88a9-ba99fa02f35b',
    ]);

    Artisan::call('about', ['--only' => 'passkeys']);

    $rendered = Artisan::output();

    // Guard the guard: `app(Kernel::class)->output()` returns '' — an empty capture would
    // make every negative assertion below pass against nothing. Prove we captured a section
    // first, on the most credential-heavy package in the fleet.
    expect($rendered)->toContain('Sign-count policy')
        ->and($rendered)->toContain('AAGUID allow-list');

    expect($rendered)
        ->not->toContain('auth.acme-internal.example')
        ->not->toContain('admin.acme-internal.example')
        ->not->toContain('ACME Internal SSO')
        ->not->toContain('acme-tenant-redis')
        ->not->toContain('acme_webauthn_handle')
        ->not->toContain('yubico-ca.pem')
        ->not->toContain('/srv/acme/secrets')
        ->not->toContain('ea9b8d66')
        ->not->toContain('d8522d9f');

    // What it reports instead: posture, presence and counts.
    expect($rendered)
        ->toContain('2 origin(s)')
        ->toContain('id SET, name SET')
        ->toContain('1 host path(s)')
        ->toContain('2 allowed')
        ->toContain('CUSTOM');
});

it('reports a missing relying party rather than inventing one', function (): void {
    config()->set('passkeys.rp.id', null);
    config()->set('passkeys.origins', []);
    config()->set('passkeys.aaguids.allowed', []);
    config()->set('passkeys.challenge.store', null);

    Artisan::call('about', ['--only' => 'passkeys']);

    $rendered = Artisan::output();

    expect($rendered)->toContain('id MISSING')
        ->and($rendered)->toContain('0 origin(s)')
        ->and($rendered)->toContain('ANY')
        ->and($rendered)->toContain('DEFAULT');
});
