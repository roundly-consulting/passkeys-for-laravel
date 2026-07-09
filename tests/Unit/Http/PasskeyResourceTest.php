<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Http\Resources\PasskeyResource;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Tests\Support\User;

beforeEach(function (): void {
    $this->user = User::query()->create(['name' => 'Res', 'email' => 'res@example.com']);
});

it('exposes only display-safe fields', function (): void {
    $passkey = Passkey::factory()->forAuthenticatable($this->user)->create(['name' => 'My Key']);

    $array = (new PasskeyResource($passkey))->resolve();

    expect($array)->toHaveKeys(['id', 'name', 'aaguid', 'transports', 'backup_eligible', 'backup_state', 'last_used_at', 'created_at'])
        ->and($array)->not->toHaveKeys(['public_key', 'user_handle', 'credential_id', 'credential_id_hash'])
        ->and($array['name'])->toBe('My Key');
});

it('never leaks key material through a json collection', function (): void {
    Passkey::factory()->forAuthenticatable($this->user)->count(2)->create();

    $json = (string) json_encode(PasskeyResource::collection($this->user->passkeys)->resolve());

    expect($json)->not->toContain('public_key')
        ->and($json)->not->toContain('user_handle')
        ->and($json)->not->toContain('credential_id');
});
