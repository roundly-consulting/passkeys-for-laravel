<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Exceptions\InvalidConfiguration;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\Support\UserHandleColumn;
use RoundlyConsulting\Passkeys\Tests\Support\User;

/*
 * The settings read outside PasskeyConfig — the table, the user-handle column, the handle
 * size and the host model's attribute names — are as strict as the rest: not set (absent,
 * null or blank) reads as the default, anything malformed throws instead of silently
 * reading as the default.
 */

it('refuses a non-string table (strict config)', function (mixed $table): void {
    config(['passkeys.table' => $table]);

    expect(fn (): string => (new Passkey)->getTable())->toThrow(InvalidConfiguration::class, 'passkeys.table');
})->with(['array' => [['passkeys']], 'int' => [1]]);

it('reads the default table when none is configured (strict config)', function (mixed $unset): void {
    config(['passkeys.table' => $unset]);

    expect((new Passkey)->getTable())->toBe('passkeys');
})->with(['null' => [null], 'blank' => [''], 'whitespace' => ['  ']]);

it('refuses a non-string user handle column (strict config)', function (mixed $column): void {
    config(['passkeys.user.handle_column' => $column]);

    expect(fn (): string => UserHandleColumn::name())->toThrow(InvalidConfiguration::class, 'passkeys.user.handle_column');
})->with(['int' => [1], 'array' => [['handle']]]);

it('reads the default user handle column when none is configured (strict config)', function (mixed $unset): void {
    config(['passkeys.user.handle_column' => $unset]);

    expect(UserHandleColumn::name())->toBe(UserHandleColumn::DEFAULT);
})->with(['null' => [null], 'blank' => [''], 'whitespace' => ['  ']]);

it('reads a blank handle size or attribute name as the default (strict config)', function (): void {
    config([
        'passkeys.user.handle_bytes' => '',
        'passkeys.user.name_attribute' => '',
        'passkeys.user.display_name_attribute' => ' ',
    ]);
    $user = User::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);

    expect(strlen(base64_decode(strtr($user->passkeyUserHandle(), '-_', '+/'), true) ?: ''))->toBe(32)
        ->and($user->passkeyUserName())->toBe('ada@example.com')
        ->and($user->passkeyDisplayName())->toBe('Ada');
});

it('refuses a junk or out-of-range handle size instead of clamping it (strict config)', function (mixed $bytes): void {
    config(['passkeys.user.handle_bytes' => $bytes]);
    $user = User::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);

    expect(fn (): string => $user->passkeyUserHandle())->toThrow(InvalidConfiguration::class, 'passkeys.user.handle_bytes');
})->with(['word' => ['many'], 'too small' => [8], 'too large' => [65]]);

it('mints a handle of the configured size from an env string (strict config)', function (): void {
    config(['passkeys.user.handle_bytes' => '48']);
    $user = User::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);

    expect(strlen(base64_decode(strtr($user->passkeyUserHandle(), '-_', '+/'), true) ?: ''))->toBe(48);
});

it('refuses a non-string user name attribute (strict config)', function (string $key, string $method): void {
    config([$key => ['email']]);
    $user = User::query()->create(['name' => 'Ada', 'email' => 'ada@example.com']);

    expect(fn () => $user->{$method}())->toThrow(InvalidConfiguration::class, $key);
})->with([
    'name' => ['passkeys.user.name_attribute', 'passkeyUserName'],
    'display name' => ['passkeys.user.display_name_attribute', 'passkeyDisplayName'],
]);
