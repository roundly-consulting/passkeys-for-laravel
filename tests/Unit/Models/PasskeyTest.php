<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\Client;
use RoundlyConsulting\Passkeys\Tests\Support\PlainOwner;
use RoundlyConsulting\Passkeys\Tests\Support\User;

it('persists a passkey through the factory', function (): void {
    $passkey = Passkey::factory()->create();

    expect($passkey->exists)->toBeTrue()
        ->and($passkey->transports)->toBeArray()
        ->and($passkey->backup_eligible)->toBeBool();
});

it('casts the flag and counter columns', function (): void {
    $passkey = Passkey::factory()->create(['sign_count' => 3, 'backup_state' => true]);

    expect($passkey->refresh()->sign_count)->toBe(3)
        ->and($passkey->backup_state)->toBeTrue();
});

it('resolves the owning model through the morph relation', function (): void {
    $user = User::query()->create(['name' => 'Edsger', 'email' => 'e@example.com']);
    $passkey = Passkey::factory()->forAuthenticatable($user)->create();

    expect($passkey->authenticatable->is($user))->toBeTrue();
});

it('gives a passkey seeded for an account that account\'s user handle', function (): void {
    $user = User::query()->create(['name' => 'Edsger', 'email' => 'e@example.com']);

    $passkey = Passkey::factory()->forAuthenticatable($user)->create();

    expect($passkey->user_handle)->toBeString()->not->toBe('')
        ->and($passkey->user_handle)->toBe($user->passkey_user_handle)
        ->and($user->fresh()?->passkey_user_handle)->toBe($passkey->user_handle);
});

it('reuses the handle an account already holds when seeding its passkeys', function (): void {
    $user = User::query()->create(['name' => 'Edsger', 'email' => 'e@example.com']);
    $handle = $user->passkeyUserHandle();

    $first = Passkey::factory()->forAuthenticatable($user)->create();
    $second = Passkey::factory()->forAuthenticatable($user->fresh() ?? $user)->create();

    expect($first->user_handle)->toBe($handle)
        ->and($second->user_handle)->toBe($handle);
});

it('leaves an owner without HasPasskeys untouched and keeps a random handle', function (): void {
    $owner = PlainOwner::query()->create(['name' => 'Plain', 'email' => 'p@example.com']);
    $before = $owner->getAttributes();

    $passkey = Passkey::factory()->forAuthenticatable($owner)->create();

    expect($owner->getAttributes())->toBe($before)
        ->and($owner->isDirty())->toBeFalse()
        ->and($owner->fresh()?->passkey_user_handle)->toBeNull()
        ->and($passkey->user_handle)->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and($passkey->authenticatable->is($owner))->toBeTrue();
});

it('scopes a query by credential id through its hash', function (): void {
    Passkey::factory()->withCredentialId('known-id')->create();

    expect(Passkey::query()->forCredentialId('known-id')->exists())->toBeTrue()
        ->and(Passkey::query()->forCredentialId('other')->exists())->toBeFalse();
});

it('stores a deterministic lookup hash for the credential id', function (): void {
    $passkey = Passkey::factory()->withCredentialId('known-id')->create();

    expect($passkey->credential_id_hash)->toBe(hash('sha256', 'known-id'))
        ->and(Passkey::hashCredentialId('known-id'))->toBe(hash('sha256', 'known-id'));
});

it('registers a long roaming-key credential id and looks it up', function (): void {
    $longId = str_repeat('A', 1364);

    Passkey::factory()->withCredentialId($longId)->create();

    expect(Passkey::query()->forCredentialId($longId)->exists())->toBeTrue();
});

it('hides key material and lookup keys from array serialisation', function (): void {
    $array = Passkey::factory()->create()->toArray();

    expect($array)->not->toHaveKeys(['public_key', 'user_handle', 'credential_id', 'credential_id_hash']);
});

it('scopes a query by user handle', function (): void {
    Passkey::factory()->create(['user_handle' => 'known-handle']);

    expect(Passkey::query()->forUserHandle('known-handle')->exists())->toBeTrue();
});

it('advances the counter and stamps last usage', function (): void {
    Carbon::setTestNow('2026-07-09 12:00:00');
    $passkey = Passkey::factory()->neverUsed()->create();

    expect($passkey->advanceSignCount(9, backupState: true))->toBeTrue()
        ->and($passkey->sign_count)->toBe(9)
        ->and($passkey->backup_state)->toBeTrue()
        ->and($passkey->isDirty())->toBeFalse()
        ->and($passkey->refresh()->sign_count)->toBe(9)
        ->and($passkey->last_used_at?->toDateTimeString())->toBe('2026-07-09 12:00:00');

    Carbon::setTestNow();
});

it('never moves the counter backwards, and reloads what is stored', function (): void {
    $passkey = Passkey::factory()->create(['sign_count' => 20, 'last_used_at' => null]);

    expect($passkey->advanceSignCount(20, backupState: true))->toBeFalse()
        ->and($passkey->advanceSignCount(4, backupState: true))->toBeFalse()
        ->and($passkey->advanceSignCount(0, backupState: true))->toBeFalse()
        ->and($passkey->sign_count)->toBe(20)
        ->and($passkey->refresh()->last_used_at)->toBeNull();
});

it('stamps usage without touching the counter or other unsaved edits', function (): void {
    Carbon::setTestNow('2026-07-09 12:00:00');
    $passkey = Passkey::factory()->create(['sign_count' => 20, 'name' => 'Laptop', 'backup_state' => true, 'last_used_at' => null]);
    $passkey->name = 'unsaved edit';

    $passkey->recordUsage(backupState: false);

    expect($passkey->last_used_at?->toDateTimeString())->toBe('2026-07-09 12:00:00')
        ->and($passkey->backup_state)->toBeFalse()
        ->and($passkey->isDirty('last_used_at'))->toBeFalse()
        ->and($passkey->isDirty('name'))->toBeTrue()
        ->and($passkey->refresh()->sign_count)->toBe(20)
        ->and($passkey->name)->toBe('Laptop');

    Carbon::setTestNow();
});

it('soft deletes rather than hard deleting', function (): void {
    $passkey = Passkey::factory()->create();

    $passkey->delete();

    expect(Passkey::query()->count())->toBe(0)
        ->and(Passkey::withTrashed()->count())->toBe(1);
});

it('honours a custom table name from config', function (): void {
    config()->set('passkeys.table', 'custom_passkeys');

    expect((new Passkey)->getTable())->toBe('custom_passkeys');
});

it('the never-used state clears usage fields', function (): void {
    $passkey = Passkey::factory()->neverUsed()->create();

    expect($passkey->sign_count)->toBe(0)
        ->and($passkey->last_used_at)->toBeNull();
});

it('provides es256 and rs256 factory states', function (): void {
    expect(Passkey::factory()->es256()->make()->attestation_format)->toBe('none')
        ->and(Passkey::factory()->rs256()->make()->attestation_format)->toBe('none');
});

it('scopes a query to exactly one owner by morph type and key', function (): void {
    $user = User::query()->create(['name' => 'Edsger', 'email' => 'e@example.com']);
    $other = User::query()->create(['name' => 'Tony', 'email' => 't@example.com']);
    $client = Client::query()->create(['name' => 'Acme']);

    $mine = Passkey::factory()->forAuthenticatable($user)->create();
    Passkey::factory()->forAuthenticatable($other)->create();
    Passkey::factory()->forAuthenticatable($client)->create(); // same key as $user, other type

    $owned = Passkey::query()->ownedBy($user)->get();

    expect($client->getKey())->toBe($user->getKey())
        ->and($owned)->toHaveCount(1)
        ->and($owned->first()?->is($mine))->toBeTrue()
        ->and(Passkey::query()->ownedBy($client)->count())->toBe(1);
});
