<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Passkeys\DataTransferObjects\CreationOptionsData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\DataTransferObjects\RequestOptionsData;
use RoundlyConsulting\Passkeys\Facades\Passkeys;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\Client;
use RoundlyConsulting\Passkeys\Tests\Support\User;

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Barbara', 'email' => 'barbara@example.com']);
});

it('exposes a morph-many passkeys relation', function (): void {
    Passkey::factory()->forAuthenticatable($this->user)->create();

    expect($this->user->passkeys()->count())->toBe(1);
});

it('lazily generates and persists an opaque user handle', function (): void {
    $handle = $this->user->passkeyUserHandle();

    expect($handle)->toBeString()->not->toBeEmpty()
        ->and($this->user->refresh()->passkey_user_handle)->toBe($handle)
        ->and(strlen(Base64Url::decode($handle)))->toBeGreaterThanOrEqual(16);
});

it('returns the same handle on repeated calls', function (): void {
    $first = $this->user->passkeyUserHandle();
    $second = $this->user->passkeyUserHandle();

    expect($second)->toBe($first);
});

it('honours an existing handle without regenerating it', function (): void {
    $this->user->forceFill(['passkey_user_handle' => 'preset-handle'])->save();

    expect($this->user->passkeyUserHandle())->toBe('preset-handle');
});

it('defaults the account and display names to the model attributes', function (): void {
    expect($this->user->passkeyUserName())->toBe('barbara@example.com')
        ->and($this->user->passkeyDisplayName())->toBe('Barbara');
});

it('repoints the name attributes through config', function (): void {
    config()->set('passkeys.user.name_attribute', 'name');
    config()->set('passkeys.user.display_name_attribute', 'email');

    expect($this->user->passkeyUserName())->toBe('Barbara')
        ->and($this->user->passkeyDisplayName())->toBe('barbara@example.com');
});

it('falls back to the key when the name attribute is missing', function (): void {
    $user = User::query()->create(['name' => null, 'email' => null]);

    expect($user->passkeyUserName())->toBe((string) $user->getKey())
        ->and($user->passkeyDisplayName())->toBe((string) $user->getKey());
});

it('builds registration options through the user verb', function (): void {
    Passkeys::fake();

    expect($this->user->passkeyRegistrationOptions())->toBeInstanceOf(CreationOptionsData::class);
});

it('builds authentication options through the user verb', function (): void {
    Passkeys::fake();

    expect($this->user->passkeyAuthenticationOptions())->toBeInstanceOf(RequestOptionsData::class);
});

it('registers a passkey through the user verb, delegating to the service', function (): void {
    $fake = Passkeys::fake();

    $response = new RegistrationResponseData(rawId: 'raw', clientDataJson: '{}', attestationObject: 'att');

    $passkey = $this->user->registerPasskey($response, 'Phone');

    expect($passkey->name)->toBe('Phone')
        ->and($passkey->authenticatable->is($this->user))->toBeTrue();

    $fake->assertRegisteredFor($this->user);
});

it('reports whether the account has passkeys and how many', function (): void {
    expect($this->user->hasPasskeys())->toBeFalse()
        ->and($this->user->passkeyCount())->toBe(0);

    Passkey::factory()->forAuthenticatable($this->user)->count(2)->create();

    expect($this->user->hasPasskeys())->toBeTrue()
        ->and($this->user->passkeyCount())->toBe(2);
});

it('ignores revoked passkeys in the presence check and count', function (): void {
    $passkey = Passkey::factory()->forAuthenticatable($this->user)->create();

    Passkeys::for($this->user)->revoke($passkey);

    expect($this->user->hasPasskeys())->toBeFalse()
        ->and($this->user->passkeyCount())->toBe(0);
});

it('does not count another owner type sharing the same key', function (): void {
    $client = Client::query()->create(['name' => 'Acme']);
    Passkey::factory()->forAuthenticatable($client)->create();

    expect($client->getKey())->toBe($this->user->getKey())
        ->and($this->user->hasPasskeys())->toBeFalse()
        ->and($client->passkeyCount())->toBe(1);
});
