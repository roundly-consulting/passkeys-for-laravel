<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Passkeys\PasskeysServiceProvider;
use RoundlyConsulting\Passkeys\Tests\Support\Client;

/**
 * `$table->passkeyUserHandle()` creates the host-owned handle column on any account
 * table. It is registered in boot() next to the toolkit macros, so it exists before a
 * host's `php artisan migrate` runs.
 */
it('registers the macro when the provider boots on its own', function (): void {
    Blueprint::flushMacros();

    expect(Blueprint::hasMacro('passkeyUserHandle'))->toBeFalse();

    $provider = new PasskeysServiceProvider(app());
    $provider->register();
    $provider->boot();

    expect(Blueprint::hasMacro('passkeyUserHandle'))->toBeTrue()
        // The toolkit macros the passkeys migration needs come back with it.
        ->and(Blueprint::hasMacro('morphKey'))->toBeTrue();
});

it('creates the handle column on a host account table', function (): void {
    expect(Schema::hasColumn('clients', 'passkey_user_handle'))->toBeTrue();
});

it('makes the handle column nullable so it can be minted lazily', function (): void {
    Client::query()->create(['name' => 'One']);
    Client::query()->create(['name' => 'Two']);

    expect(Client::query()->whereNull('passkey_user_handle')->count())->toBe(2);
});

it('makes the handle column unique so a handle resolves one account', function (): void {
    Client::query()->create(['name' => 'One', 'passkey_user_handle' => 'same']);
    Client::query()->create(['name' => 'Two', 'passkey_user_handle' => 'same']);
})->throws(QueryException::class);

it('persists a lazily minted handle into the macro-built column', function (): void {
    $client = Client::query()->create(['name' => 'Acme']);

    $handle = $client->passkeyUserHandle();

    expect($client->fresh()?->passkey_user_handle)->toBe($handle);
});

it('names the column after passkeys.user.handle_column', function (): void {
    config()->set('passkeys.user.handle_column', 'webauthn_handle');

    Schema::create('accounts', function (Blueprint $table): void {
        $table->id();
        $table->passkeyUserHandle();
    });

    expect(Schema::hasColumn('accounts', 'webauthn_handle'))->toBeTrue()
        ->and(Schema::hasColumn('accounts', 'passkey_user_handle'))->toBeFalse();
});
