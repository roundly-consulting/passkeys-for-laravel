<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use RoundlyConsulting\Passkeys\Models\Passkey;
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

it('scopes a query by credential id', function (): void {
    Passkey::factory()->create(['credential_id' => 'known-id']);

    expect(Passkey::query()->forCredentialId('known-id')->exists())->toBeTrue()
        ->and(Passkey::query()->forCredentialId('other')->exists())->toBeFalse();
});

it('scopes a query by user handle', function (): void {
    Passkey::factory()->create(['user_handle' => 'known-handle']);

    expect(Passkey::query()->forUserHandle('known-handle')->exists())->toBeTrue();
});

it('advances the counter and stamps last usage', function (): void {
    Carbon::setTestNow('2026-07-09 12:00:00');
    $passkey = Passkey::factory()->neverUsed()->create();

    $passkey->touchUsage(9);

    expect($passkey->refresh()->sign_count)->toBe(9)
        ->and($passkey->last_used_at?->toDateTimeString())->toBe('2026-07-09 12:00:00');

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
