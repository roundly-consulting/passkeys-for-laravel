<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\Cose\CborDecoder;
use RoundlyConsulting\Passkeys\Testing\CborEncoder;

/**
 * The test-only encoder is proven against crypto's production decoder: whatever it
 * builds must decode back to the value it was asked to encode.
 */
it('encodes values the production decoder reads back', function (string $encoded, mixed $expected): void {
    expect((new CborDecoder)->decode($encoded))->toBe($expected);
})->with([
    'small uint' => [CborEncoder::uint(23), 23],
    '1-byte uint' => [CborEncoder::uint(200), 200],
    '2-byte uint' => [CborEncoder::uint(0x1234), 0x1234],
    '4-byte uint' => [CborEncoder::uint(0x12345678), 0x12345678],
    '8-byte uint' => [CborEncoder::uint(0x123456789A), 0x123456789A],
    'negative int' => [CborEncoder::nint(-257), -257],
    'byte string' => [CborEncoder::bstr("\x00\x01"), "\x00\x01"],
    'text string' => [CborEncoder::tstr('none'), 'none'],
    'array' => [CborEncoder::arr([CborEncoder::uint(1), CborEncoder::tstr('a')]), [1, 'a']],
    'map' => [CborEncoder::map([[CborEncoder::uint(1), CborEncoder::uint(2)]]), [1 => 2]],
    'true' => [CborEncoder::simple(true), true],
    'false' => [CborEncoder::simple(false), false],
]);
