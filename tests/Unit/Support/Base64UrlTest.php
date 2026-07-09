<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Exceptions\InvalidClientData;
use RoundlyConsulting\Passkeys\Support\Base64Url;

it('round-trips arbitrary binary without padding', function (string $binary): void {
    $encoded = Base64Url::encode($binary);

    expect($encoded)
        ->not->toContain('=')
        ->not->toContain('+')
        ->not->toContain('/');

    expect(Base64Url::decode($encoded))->toBe($binary);
})->with([
    'empty' => [''],
    'single byte' => ["\xff"],
    'two bytes' => ["\xfb\xff"],
    'random 32' => [random_bytes(32)],
    'text' => ['hello world'],
]);

it('decodes an empty string to an empty string', function (): void {
    expect(Base64Url::decode(''))->toBe('');
});

it('rejects characters outside the base64url alphabet', function (): void {
    Base64Url::decode('abc+def');
})->throws(InvalidClientData::class);

it('rejects base64url with padding characters', function (): void {
    Base64Url::decode('YWJj=');
})->throws(InvalidClientData::class);

it('rejects whitespace and other non-alphabet bytes', function (): void {
    Base64Url::decode('abc def');
})->throws(InvalidClientData::class);

it('rejects an alphabet-only string of an impossible length', function (): void {
    // Five base64 characters (4n+1) can never decode to whole bytes.
    Base64Url::decode('ABCDE');
})->throws(InvalidClientData::class);

it('produces the canonical url-safe alphabet', function (): void {
    // 0xFB 0xFF encodes to "+/" in standard base64 -> "-_" in url-safe.
    expect(Base64Url::encode("\xfb\xff"))->toBe('-_8');
});
