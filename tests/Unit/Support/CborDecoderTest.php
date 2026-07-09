<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Exceptions\MalformedCbor;
use RoundlyConsulting\Passkeys\Support\CborDecoder;
use RoundlyConsulting\Passkeys\Tests\Support\CborEncoder;

beforeEach(function (): void {
    $this->cbor = new CborDecoder;
});

it('decodes unsigned integers of every width', function (int $value): void {
    expect($this->cbor->decode(CborEncoder::uint($value)))->toBe($value);
})->with([
    'tiny' => [5],
    'one byte' => [200],
    'two bytes' => [40_000],
    'four bytes' => [3_000_000_000],
    'eight bytes' => [5_000_000_000],
]);

it('decodes negative integers', function (): void {
    expect($this->cbor->decode(CborEncoder::nint(-7)))->toBe(-7);
    expect($this->cbor->decode(CborEncoder::nint(-257)))->toBe(-257);
});

it('decodes byte and text strings', function (): void {
    expect($this->cbor->decode(CborEncoder::bstr("\x01\x02\x03")))->toBe("\x01\x02\x03");
    expect($this->cbor->decode(CborEncoder::tstr('fido')))->toBe('fido');
});

it('decodes definite-length arrays', function (): void {
    $encoded = CborEncoder::arr([CborEncoder::uint(1), CborEncoder::uint(2), CborEncoder::tstr('x')]);

    expect($this->cbor->decode($encoded))->toBe([1, 2, 'x']);
});

it('decodes maps with integer and string keys', function (): void {
    $encoded = CborEncoder::map([
        [CborEncoder::uint(1), CborEncoder::uint(2)],
        [CborEncoder::tstr('fmt'), CborEncoder::tstr('none')],
    ]);

    expect($this->cbor->decode($encoded))->toBe([1 => 2, 'fmt' => 'none']);
});

it('decodes the three simple values', function (): void {
    expect($this->cbor->decode(CborEncoder::simple(true)))->toBeTrue();
    expect($this->cbor->decode(CborEncoder::simple(false)))->toBeFalse();
    expect($this->cbor->decode("\xf6"))->toBeNull(); // null
});

it('reports how many bytes the first item consumed', function (): void {
    $buffer = CborEncoder::uint(9).'TRAILING';

    [$value, $consumed] = $this->cbor->decodeFirst($buffer);

    expect($value)->toBe(9)->and($consumed)->toBe(1);
});

it('rejects trailing bytes after a top-level item', function (): void {
    $this->cbor->decode(CborEncoder::uint(1).'x');
})->throws(MalformedCbor::class);

it('rejects unsupported major type tags', function (): void {
    $this->cbor->decode("\xc0\x00"); // major type 6 (tag)
})->throws(MalformedCbor::class);

it('rejects indefinite-length items', function (): void {
    $this->cbor->decode("\x5f"); // byte string, additional info 31 (indefinite)
})->throws(MalformedCbor::class);

it('rejects unsupported simple values and floats', function (): void {
    $this->cbor->decode("\xfa\x00\x00\x00\x00"); // float32
})->throws(MalformedCbor::class);

it('rejects maps with non-scalar keys', function (): void {
    $encoded = "\xa1".CborEncoder::arr([CborEncoder::uint(1)]).CborEncoder::uint(2);

    $this->cbor->decode($encoded);
})->throws(MalformedCbor::class);

it('rejects a declared length that exceeds the remaining input', function (): void {
    $this->cbor->decode("\x45\x01\x02"); // byte string of 5, only 2 present
})->throws(MalformedCbor::class);

it('rejects nesting deeper than the depth cap', function (): void {
    $payload = str_repeat("\x81", 20).CborEncoder::uint(1); // 20 nested arrays

    $this->cbor->decode($payload);
})->throws(MalformedCbor::class);

it('rejects an unexpected end of input', function (): void {
    $this->cbor->decode('');
})->throws(MalformedCbor::class);

it('rejects a length that overflows the supported integer range', function (): void {
    $this->cbor->decode("\x1b\xff\xff\xff\xff\xff\xff\xff\xff"); // 8-byte length, all bits set
})->throws(MalformedCbor::class);

it('rejects an array declaring more items than the remaining input', function (): void {
    $this->cbor->decode("\x98\x64"); // array of 100 with no items present
})->throws(MalformedCbor::class);

it('throws cleanly for every truncation of a valid buffer', function (): void {
    $valid = CborEncoder::map([
        [CborEncoder::tstr('fmt'), CborEncoder::tstr('none')],
        [CborEncoder::tstr('data'), CborEncoder::bstr(random_bytes(8))],
    ]);

    for ($length = 1; $length < strlen($valid); $length++) {
        expect(fn () => (new CborDecoder)->decode(substr($valid, 0, $length)))
            ->toThrow(MalformedCbor::class);
    }
});
