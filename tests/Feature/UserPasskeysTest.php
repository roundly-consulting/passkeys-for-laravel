<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Passkeys\Actions\RenamePasskeyAction;
use RoundlyConsulting\Passkeys\Actions\RevokePasskeyAction;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Events\PasskeyRenamed;
use RoundlyConsulting\Passkeys\Events\PasskeyRevoked;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\PasskeyManager;
use RoundlyConsulting\Passkeys\Tests\Support\Client;
use RoundlyConsulting\Passkeys\Tests\Support\User;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;
use RoundlyConsulting\Passkeys\UserPasskeys;

function handleEnrol(User|Client $owner, WebAuthnVectors $vectors, ?string $name = null): Passkey
{
    $options = Passkeys::for($owner)->registrationOptions();

    return Passkeys::for($owner)->register(RegistrationResponseData::fromArray($vectors->registrationResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
    ])), $name);
}

function handleAssertion(RequestOptionsData $options, WebAuthnVectors $vectors): AuthenticationResponseData
{
    return AuthenticationResponseData::fromArray($vectors->assertionResponse([
        'challenge' => $options->challenge,
        'ceremonyId' => $options->ceremonyId,
        'signCount' => 7,
    ]));
}

beforeEach(function (): void {
    $this->alice = User::query()->create(['name' => 'Alice', 'email' => 'alice@example.com']);
    $this->bob = User::query()->create(['name' => 'Bob', 'email' => 'bob@example.com']);
});

afterEach(function (): void {
    Carbon::setTestNow();
});

it('runs an account-bound ceremony through Passkeys::for()', function (): void {
    $vectors = WebAuthnVectors::es256();
    $keys = Passkeys::for($this->alice);

    expect($keys)->toBeInstanceOf(UserPasskeys::class)
        ->and($keys->exists())->toBeFalse();

    $passkey = handleEnrol($this->alice, $vectors, 'Laptop');

    $options = $keys->authenticationOptions();

    expect($options->allowCredentials)->toHaveCount(1);

    $authenticated = $keys->authenticate(handleAssertion($options, $vectors));

    expect($authenticated->is($passkey))->toBeTrue()
        ->and($authenticated->sign_count)->toBe(7);
});

it('lists, finds and counts only the account\'s active passkeys', function (): void {
    Carbon::setTestNow('2026-01-01 10:00:00');
    $older = Passkey::factory()->forAuthenticatable($this->alice)->create();
    Carbon::setTestNow('2026-01-02 10:00:00');
    $newer = Passkey::factory()->forAuthenticatable($this->alice)->create();
    $revoked = Passkey::factory()->forAuthenticatable($this->alice)->create();
    $revoked->delete();
    $bobs = Passkey::factory()->forAuthenticatable($this->bob)->create();

    $keys = Passkeys::for($this->alice);

    expect($keys->all()->modelKeys())->toBe([$newer->getKey(), $older->getKey()])
        ->and($keys->count())->toBe(2)
        ->and($keys->exists())->toBeTrue()
        ->and($keys->find($older->getKey())?->is($older))->toBeTrue()
        ->and($keys->find($revoked->getKey()))->toBeNull()
        ->and($keys->find($bobs->getKey()))->toBeNull();
});

it('renames and revokes by id or by model', function (): void {
    Event::fake([PasskeyRenamed::class, PasskeyRevoked::class]);
    $first = Passkey::factory()->forAuthenticatable($this->alice)->create(['name' => 'Old']);
    $second = Passkey::factory()->forAuthenticatable($this->alice)->create();

    $renamed = Passkeys::for($this->alice)->rename($first->getKey(), 'Work laptop');

    expect($renamed->name)->toBe('Work laptop')
        ->and($first->refresh()->name)->toBe('Work laptop');

    Passkeys::for($this->alice)->rename($second, 'Phone');
    Passkeys::for($this->alice)->revoke($first->getKey());
    Passkeys::for($this->alice)->revoke($second);

    expect($first->refresh()->trashed())->toBeTrue()
        ->and($second->refresh()->trashed())->toBeTrue()
        ->and(Passkeys::for($this->alice)->count())->toBe(0);
    Event::assertDispatchedTimes(PasskeyRenamed::class, 2);
    Event::assertDispatchedTimes(PasskeyRevoked::class, 2);
});

it('takes a route parameter — a string id — straight through', function (): void {
    Event::fake([PasskeyRenamed::class, PasskeyRevoked::class]);
    $passkey = Passkey::factory()->forAuthenticatable($this->alice)->create(['name' => 'Old']);
    $routeParameter = (string) $passkey->getKey();

    $keys = Passkeys::for($this->alice);

    expect($keys->find($routeParameter)?->is($passkey))->toBeTrue()
        ->and($keys->rename($routeParameter, 'Work laptop')->name)->toBe('Work laptop');

    $keys->revoke($routeParameter);

    expect($passkey->refresh()->trashed())->toBeTrue();
    Event::assertDispatched(PasskeyRenamed::class);
    Event::assertDispatched(PasskeyRevoked::class);
});

it('treats a string that is not a positive integer id as not found', function (string $id): void {
    $passkey = Passkey::factory()->forAuthenticatable($this->alice)->create(['name' => 'Keep']);

    $keys = Passkeys::for($this->alice);

    expect($keys->find($id))->toBeNull()
        ->and(fn () => $keys->rename($id, 'Stolen'))->toThrow(CredentialNotFound::class)
        ->and(fn () => $keys->revoke($id))->toThrow(CredentialNotFound::class)
        ->and($passkey->refresh()->name)->toBe('Keep')
        ->and($passkey->trashed())->toBeFalse();
})->with([
    'not a number' => ['abc'],
    'a decimal' => ['1.5'],
    'negative' => ['-1'],
    'zero' => ['0'],
    'empty' => [''],
    'padded' => [' 1'],
    'leading zero' => ['01'],
    'overflowing' => ['99999999999999999999'],
]);

it('refuses to rename or revoke another account\'s passkey', function (string $verb, bool $byId): void {
    $bobs = Passkey::factory()->forAuthenticatable($this->bob)->create(['name' => 'Bob key']);
    $target = $byId ? $bobs->getKey() : $bobs;

    expect(fn () => $verb === 'rename'
        ? Passkeys::for($this->alice)->rename($target, 'Stolen')
        : Passkeys::for($this->alice)->revoke($target))
        ->toThrow(CredentialNotFound::class);

    expect($bobs->refresh()->name)->toBe('Bob key')
        ->and($bobs->trashed())->toBeFalse();
})->with([
    'rename by id' => ['rename', true],
    'rename by model' => ['rename', false],
    'revoke by id' => ['revoke', true],
    'revoke by model' => ['revoke', false],
]);

it('refuses a passkey of another owner type sharing the same key', function (): void {
    $client = Client::query()->create(['name' => 'Acme', 'email' => 'acme@example.com']);
    $clientKey = Passkey::factory()->forAuthenticatable($client)->create();

    expect($client->getKey())->toBe($this->alice->getKey())
        ->and(Passkeys::for($this->alice)->find($clientKey->getKey()))->toBeNull()
        ->and(fn () => Passkeys::for($this->alice)->revoke($clientKey))->toThrow(CredentialNotFound::class);
});

it('refuses to touch an already revoked passkey', function (): void {
    $passkey = Passkey::factory()->forAuthenticatable($this->alice)->create();
    Passkeys::for($this->alice)->revoke($passkey);

    Passkeys::for($this->alice)->rename($passkey, 'Back from the dead');
})->throws(CredentialNotFound::class);

it('refuses another account\'s credential in an account-bound authentication', function (): void {
    $vectors = WebAuthnVectors::es256();
    $bobsPasskey = handleEnrol($this->bob, $vectors);

    $options = Passkeys::authenticationOptions();

    expect(fn () => Passkeys::for($this->alice)->authenticate(handleAssertion($options, $vectors)))
        ->toThrow(CredentialNotFound::class);

    // The ceremony is still live for the rightful owner.
    expect(Passkeys::for($this->bob)->authenticate(handleAssertion($options, $vectors))->is($bobsPasskey))->toBeTrue();
});

it('lists the attestation formats it can verify', function (): void {
    expect(Passkeys::attestationFormats())->toBe(['none', 'packed', 'apple']);
});

it('serves the same API to an injected PasskeyService', function (): void {
    $service = app(PasskeyService::class);
    Passkey::factory()->forAuthenticatable($this->alice)->create();

    expect($service)->toBeInstanceOf(PasskeyManager::class)
        ->and($service->for($this->alice)->count())->toBe(1)
        ->and($service->authenticationOptions()->allowCredentials)->toBe([])
        ->and($service->attestationFormats())->toContain('packed');
});

it('runs the rename action on its own', function (): void {
    Event::fake([PasskeyRenamed::class]);
    $passkey = Passkey::factory()->forAuthenticatable($this->alice)->create(['name' => 'Before']);

    $renamed = app(RenamePasskeyAction::class)->execute($passkey, 'After');

    expect($renamed->refresh()->name)->toBe('After');
    Event::assertDispatched(PasskeyRenamed::class, fn (PasskeyRenamed $event): bool => $event->previousName === 'Before');
});

it('runs the revoke action on its own', function (): void {
    Event::fake([PasskeyRevoked::class]);
    $passkey = Passkey::factory()->forAuthenticatable($this->alice)->create();

    app(RevokePasskeyAction::class)->execute($passkey);

    expect($passkey->refresh()->trashed())->toBeTrue();
    Event::assertDispatched(PasskeyRevoked::class);
});
