<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use RoundlyConsulting\Passkeys\Exceptions\MalformedCbor;

/**
 * A deliberately minimal, defensive CBOR (RFC 8949) decoder.
 *
 * It supports only the subset WebAuthn attestation objects and COSE keys use:
 * unsigned/negative integers, byte strings, text strings, definite-length
 * arrays and maps, and the three simple values false/true/null. Everything else
 * — indefinite lengths, tags, floats, other simple values — is rejected. Depth
 * is capped and every declared length is bounds-checked against the remaining
 * input, so hostile input can never cause a fatal error or unbounded work.
 */
final class CborDecoder
{
    private const MAX_DEPTH = 16;

    /**
     * Decode exactly one top-level item. Trailing bytes are rejected, which is
     * required for the attestationObject (it must be a single CBOR map).
     *
     * @throws MalformedCbor
     */
    public function decode(string $bytes): mixed
    {
        [$value, $consumed] = $this->decodeFirst($bytes);

        if ($consumed !== strlen($bytes)) {
            throw MalformedCbor::make('trailing bytes after top-level item');
        }

        return $value;
    }

    /**
     * Decode the first item and report how many bytes it consumed. Used to
     * locate the length-delimited COSE key that trails attested credential data.
     *
     * @return array{0: mixed, 1: int}
     *
     * @throws MalformedCbor
     */
    public function decodeFirst(string $bytes): array
    {
        $offset = 0;
        $value = $this->readItem($bytes, $offset, 0);

        return [$value, $offset];
    }

    /**
     * @throws MalformedCbor
     */
    private function readItem(string $bytes, int &$offset, int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            throw MalformedCbor::make('maximum nesting depth exceeded');
        }

        $initial = $this->readByte($bytes, $offset);
        $major = $initial >> 5;
        $additional = $initial & 0x1F;

        return match ($major) {
            0 => $this->readLength($bytes, $offset, $additional),
            1 => -1 - $this->readLength($bytes, $offset, $additional),
            2 => $this->readBytes($bytes, $offset, $this->readLength($bytes, $offset, $additional)),
            3 => $this->readBytes($bytes, $offset, $this->readLength($bytes, $offset, $additional)),
            4 => $this->readArray($bytes, $offset, $this->readLength($bytes, $offset, $additional), $depth),
            5 => $this->readMap($bytes, $offset, $this->readLength($bytes, $offset, $additional), $depth),
            7 => $this->readSimple($additional),
            default => throw MalformedCbor::make('unsupported major type '.$major),
        };
    }

    private function readByte(string $bytes, int &$offset): int
    {
        if ($offset >= strlen($bytes)) {
            throw MalformedCbor::make('unexpected end of input');
        }

        return ord($bytes[$offset++]);
    }

    /**
     * Resolve the argument (length / integer value) from the additional-info bits.
     */
    private function readLength(string $bytes, int &$offset, int $additional): int
    {
        if ($additional < 24) {
            return $additional;
        }

        $count = match ($additional) {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            default => throw MalformedCbor::make('reserved or indefinite length'),
        };

        $chunk = $this->readBytes($bytes, $offset, $count);
        $value = 0;

        foreach (str_split($chunk) as $byte) {
            $value = ($value << 8) | ord($byte);
        }

        if ($value < 0) {
            throw MalformedCbor::make('length exceeds supported range');
        }

        return $value;
    }

    private function readBytes(string $bytes, int &$offset, int $length): string
    {
        if ($length < 0 || $offset + $length > strlen($bytes)) {
            throw MalformedCbor::make('declared length exceeds remaining input');
        }

        $slice = substr($bytes, $offset, $length);
        $offset += $length;

        return $slice;
    }

    /**
     * @return list<mixed>
     */
    private function readArray(string $bytes, int &$offset, int $length, int $depth): array
    {
        if ($offset + $length > strlen($bytes)) {
            throw MalformedCbor::make('array length exceeds remaining input');
        }

        $items = [];

        for ($i = 0; $i < $length; $i++) {
            $items[] = $this->readItem($bytes, $offset, $depth + 1);
        }

        return $items;
    }

    /**
     * @return array<int|string, mixed>
     */
    private function readMap(string $bytes, int &$offset, int $length, int $depth): array
    {
        if ($offset + $length > strlen($bytes)) {
            throw MalformedCbor::make('map length exceeds remaining input');
        }

        $map = [];

        for ($i = 0; $i < $length; $i++) {
            $key = $this->readItem($bytes, $offset, $depth + 1);

            if (! is_int($key) && ! is_string($key)) {
                throw MalformedCbor::make('map keys must be integers or strings');
            }

            $map[$key] = $this->readItem($bytes, $offset, $depth + 1);
        }

        return $map;
    }

    private function readSimple(int $additional): ?bool
    {
        return match ($additional) {
            20 => false,
            21 => true,
            22 => null,
            default => throw MalformedCbor::make('unsupported simple value or float'),
        };
    }
}
