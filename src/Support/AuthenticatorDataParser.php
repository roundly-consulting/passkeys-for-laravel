<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Support;

use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticatorFlags;
use RoundlyConsulting\Passkeys\DataTransferObjects\ParsedAuthenticatorData;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;

/**
 * Parses the WebAuthn authenticatorData byte structure (spec §6.1):
 * 32-byte rpIdHash, 1 flag byte, 4-byte big-endian sign counter, and — when the
 * AT flag is set — attested credential data (16-byte AAGUID, 2-byte credential
 * id length, credential id, and the length-delimited COSE public key).
 */
final class AuthenticatorDataParser
{
    public function __construct(
        private readonly CborDecoder $cbor,
        private readonly CoseKey $coseKey,
    ) {}

    public function parse(string $bytes): ParsedAuthenticatorData
    {
        if (strlen($bytes) < 37) {
            throw InvalidAuthenticatorData::make();
        }

        $rpIdHash = substr($bytes, 0, 32);
        $flags = AuthenticatorFlags::fromByte(ord($bytes[32]));

        $signCount = unpack('N', substr($bytes, 33, 4));

        if ($signCount === false) {
            throw InvalidAuthenticatorData::make();
        }

        $offset = 37;

        if (! $flags->attestedCredentialData) {
            $this->assertNoTrailingData($bytes, $offset, $flags->extensionData);

            return new ParsedAuthenticatorData(
                rpIdHash: $rpIdHash,
                flags: $flags,
                signCount: (int) $signCount[1],
            );
        }

        return $this->parseAttested($bytes, $offset, $rpIdHash, $flags, (int) $signCount[1]);
    }

    private function parseAttested(
        string $bytes,
        int $offset,
        string $rpIdHash,
        AuthenticatorFlags $flags,
        int $signCount,
    ): ParsedAuthenticatorData {
        if ($offset + 18 > strlen($bytes)) {
            throw InvalidAuthenticatorData::attestedDataMissing();
        }

        $aaguid = substr($bytes, $offset, 16);
        $offset += 16;

        $lengthBytes = unpack('n', substr($bytes, $offset, 2));

        if ($lengthBytes === false) {
            throw InvalidAuthenticatorData::make();
        }

        $credentialIdLength = (int) $lengthBytes[1];
        $offset += 2;

        if ($credentialIdLength < 1 || $offset + $credentialIdLength > strlen($bytes)) {
            throw InvalidAuthenticatorData::make();
        }

        $credentialId = substr($bytes, $offset, $credentialIdLength);
        $offset += $credentialIdLength;

        // The COSE key is length-delimited; decodeFirst reports how far it ran so
        // any trailing extension map can be located and validated.
        [$decoded, $consumed] = $this->cbor->decodeFirst(substr($bytes, $offset));

        if (! is_array($decoded)) {
            throw InvalidAuthenticatorData::make();
        }

        $coseKeyBytes = substr($bytes, $offset, $consumed);
        $offset += $consumed;

        $this->assertNoTrailingData($bytes, $offset, $flags->extensionData);

        return new ParsedAuthenticatorData(
            rpIdHash: $rpIdHash,
            flags: $flags,
            signCount: $signCount,
            aaguid: $aaguid,
            credentialId: $credentialId,
            coseKey: $this->coseKey->fromDecoded($decoded),
            coseKeyBytes: $coseKeyBytes,
        );
    }

    /**
     * Extensions are ignored, but the structure must still terminate cleanly:
     * exactly one CBOR extension map when ED is set, and nothing otherwise.
     */
    private function assertNoTrailingData(string $bytes, int $offset, bool $extensionData): void
    {
        $remaining = strlen($bytes) - $offset;

        if (! $extensionData) {
            if ($remaining !== 0) {
                throw InvalidAuthenticatorData::make();
            }

            return;
        }

        if ($remaining < 1) {
            throw InvalidAuthenticatorData::make();
        }

        [$decoded, $consumed] = $this->cbor->decodeFirst(substr($bytes, $offset));

        if (! is_array($decoded) || $consumed !== $remaining) {
            throw InvalidAuthenticatorData::make();
        }
    }
}
