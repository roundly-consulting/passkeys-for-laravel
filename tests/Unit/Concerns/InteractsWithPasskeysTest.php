<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\Base64Url;
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
