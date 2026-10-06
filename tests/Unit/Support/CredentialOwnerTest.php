<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Relations\Relation;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\CredentialOwner;
use RoundlyConsulting\Passkeys\Tests\Support\AbstractOwner;
use RoundlyConsulting\Passkeys\Tests\Support\PlainOwner;
use RoundlyConsulting\Passkeys\Tests\Support\User;

beforeEach(function (): void {
    $this->morphMap = Relation::morphMap();
});

afterEach(function (): void {
    Relation::morphMap($this->morphMap, false);
});

it('resolves an owner type given as a class or through the morph map', function (): void {
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $passkey = Passkey::factory()->forAuthenticatable($user)->create();

    expect($passkey->authenticatable_type)->toBe(User::class)
        ->and(CredentialOwner::holds($passkey))->toBeTrue();

    Relation::morphMap(['account' => User::class]);
    $passkey->forceFill(['authenticatable_type' => 'account'])->save();

    expect(CredentialOwner::holds($passkey))->toBeTrue();
});

it('refuses an owner type that names no model, without resolving it', function (string $type): void {
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $passkey = Passkey::factory()->forAuthenticatable($user)->create();
    $passkey->forceFill(['authenticatable_type' => $type])->save();

    expect(CredentialOwner::holds($passkey))->toBeFalse();
})->with([
    'the factory default' => 'user',
    'a missing class' => 'App\\Models\\RetiredUser',
    'a class that is no model' => stdClass::class,
    'an abstract model' => AbstractOwner::class,
]);

it('checks an owner without HasPasskeys for existence only', function (): void {
    $owner = PlainOwner::query()->create(['name' => 'Plain', 'email' => 'p@example.com']);
    $passkey = Passkey::factory()->forAuthenticatable($owner)->create();

    expect(CredentialOwner::holds($passkey))->toBeTrue();

    $owner->delete();

    expect(CredentialOwner::holds($passkey))->toBeFalse();
});

it('does not load the owner onto the passkey it checks', function (): void {
    $user = User::query()->create(['name' => 'Grace', 'email' => 'grace@example.com']);
    $passkey = Passkey::factory()->forAuthenticatable($user)->create();

    expect(CredentialOwner::holds($passkey))->toBeTrue()
        ->and($passkey->relationLoaded('authenticatable'))->toBeFalse();
});
