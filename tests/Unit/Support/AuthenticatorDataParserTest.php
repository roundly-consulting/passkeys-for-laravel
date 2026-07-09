<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Enums\CoseAlgorithm;
use RoundlyConsulting\Passkeys\Exceptions\InvalidAuthenticatorData;
use RoundlyConsulting\Passkeys\Support\AuthenticatorDataParser;
use RoundlyConsulting\Passkeys\Support\CborDecoder;
use RoundlyConsulting\Passkeys\Support\CoseKey;
use RoundlyConsulting\Passkeys\Tests\Support\CborEncoder;
use RoundlyConsulting\Passkeys\Tests\Support\WebAuthnVectors;

beforeEach(function (): void {
    $this->parser = new AuthenticatorDataParser(new CborDecoder, new CoseKey);
});

function rpHash(string $rpId = 'example.com'): string
{
    return hash('sha256', $rpId, true);
}

it('parses assertion authenticator data without attested credential data', function (): void {
    $bytes = rpHash().chr(0x05).pack('N', 42);

    $parsed = $this->parser->parse($bytes);

    expect($parsed->rpIdHash)->toBe(rpHash())
        ->and($parsed->signCount)->toBe(42)
        ->and($parsed->flags->userPresent)->toBeTrue()
        ->and($parsed->flags->userVerified)->toBeTrue()
        ->and($parsed->flags->attestedCredentialData)->toBeFalse()
        ->and($parsed->coseKey)->toBeNull();
});

it('decodes every flag bit', function (): void {
    $bytes = rpHash().chr(0x5D).pack('N', 0); // UP|UV|BE|BS|AT ... plus we test bits individually below
    // 0x5D = 0101 1101 -> UP(0) UV(2) BE(3) BS(4) AT(6)
    $bytes .= str_repeat("\x11", 16).pack('n', 4).'abcd'.WebAuthnVectors::es256()->coseKey();

    $parsed = $this->parser->parse($bytes);

    expect($parsed->flags->userPresent)->toBeTrue()
        ->and($parsed->flags->userVerified)->toBeTrue()
        ->and($parsed->flags->backupEligible)->toBeTrue()
        ->and($parsed->flags->backupState)->toBeTrue()
        ->and($parsed->flags->attestedCredentialData)->toBeTrue()
        ->and($parsed->flags->extensionData)->toBeFalse();
});

it('parses attested credential data including the COSE key', function (): void {
    $vectors = WebAuthnVectors::es256();
    $credentialId = $vectors->credentialId();
    $cose = $vectors->coseKey();

    $bytes = rpHash().chr(0x45).pack('N', 0)
        .str_repeat("\x22", 16).pack('n', strlen($credentialId)).$credentialId.$cose;

    $parsed = $this->parser->parse($bytes);

    expect($parsed->credentialId)->toBe($credentialId)
        ->and($parsed->aaguid)->toBe(str_repeat("\x22", 16))
        ->and($parsed->coseKeyBytes)->toBe($cose)
        ->and($parsed->coseKey?->algorithm)->toBe(CoseAlgorithm::ES256);
});

it('accepts a trailing extension map when the ED flag is set', function (): void {
    $vectors = WebAuthnVectors::es256();
    $extensions = CborEncoder::map([[CborEncoder::tstr('devicePubKey'), CborEncoder::uint(1)]]);

    $bytes = rpHash().chr(0x85).pack('N', 3).$extensions; // ED|UV|UP, no attested data

    $parsed = $this->parser->parse($bytes);

    expect($parsed->flags->extensionData)->toBeTrue()
        ->and($parsed->signCount)->toBe(3);
});

it('rejects authenticator data shorter than the fixed header', function (): void {
    $this->parser->parse(str_repeat("\x00", 36));
})->throws(InvalidAuthenticatorData::class);

it('rejects attested data that is truncated before the aaguid', function (): void {
    $bytes = rpHash().chr(0x45).pack('N', 0).'short';

    $this->parser->parse($bytes);
})->throws(InvalidAuthenticatorData::class);

it('rejects a zero-length credential id', function (): void {
    $bytes = rpHash().chr(0x45).pack('N', 0).str_repeat("\x00", 16).pack('n', 0).WebAuthnVectors::es256()->coseKey();

    $this->parser->parse($bytes);
})->throws(InvalidAuthenticatorData::class);

it('rejects unexpected trailing bytes when no extension flag is set', function (): void {
    $bytes = rpHash().chr(0x05).pack('N', 1).'trailing';

    $this->parser->parse($bytes);
})->throws(InvalidAuthenticatorData::class);

it('rejects a missing extension map when the ED flag is set', function (): void {
    $bytes = rpHash().chr(0x85).pack('N', 1); // ED set but nothing follows

    $this->parser->parse($bytes);
})->throws(InvalidAuthenticatorData::class);
