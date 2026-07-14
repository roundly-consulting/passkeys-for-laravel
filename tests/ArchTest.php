<?php

declare(strict_types=1);

// Independence guard: the production relying party must implement WebAuthn/FIDO2
// on our own crypto-for-laravel and never reach for a third-party crypto, CBOR,
// or WebAuthn library. Allow-listing the permitted roots bans every other vendor
// implicitly — no competitor is ever named.
arch('src only uses allowed vendor roots')
    ->expect('RoundlyConsulting\Passkeys')
    ->toOnlyUse([
        'RoundlyConsulting\Passkeys',
        'RoundlyConsulting\Passkeys\Database\Factories',
        'RoundlyConsulting\Crypto',
        'RoundlyConsulting\Enums',
        'RoundlyConsulting\PackageToolkit',
        'Illuminate',
        'Carbon',
        'JsonSerializable',
        'RuntimeException',
        // native helpers used unqualified
        'app',
        'class_basename',
        'config',
        'config_path',
        'database_path',
        'now',
        '__',
    ]);

arch('no forbidden crypto, cbor, or webauthn vendors are imported')
    ->expect([
        'Webauthn',
        'Cose',
        'CBOR',
        'Spomky',
        'Base64Url\\',
        'ParagonIE',
        'phpseclib',
        'phpseclib3',
        'Firebase\\JWT',
        'lbuchs',
        'web-auth',
    ])
    ->not->toBeUsed();

/*
 * Primitives belong to crypto-for-laravel: CBOR/COSE decoding, ECDSA DER↔raw,
 * SPKI assembly, RSA/ECDSA/Ed25519 verification, base64(url), SHA-256, and the
 * constant-time compare. None of them may be re-implemented here — this package
 * owns the *ceremony* (challenge binding, origin, rpIdHash, UP/UV policy,
 * sign-count reconciliation, attestation trust), never the maths.
 *
 * Attestation trust is exempt in spirit: if a future packed/tpm verifier needs an
 * X.509 chain, that is a trust decision — not a generic algorithm — and it stays
 * in Attestation\*. Nothing there touches openssl today, so the rule can stay
 * package-wide; scope it around Attestation\* the day such a verifier lands.
 */
arch('no crypto primitive is re-implemented locally')
    ->expect('RoundlyConsulting\Passkeys')
    ->not->toUse([
        'hash',
        'hash_hmac',
        'hash_equals',
        'openssl_sign',
        'openssl_verify',
        'openssl_pkey_new',
        'openssl_pkey_get_public',
        'openssl_pkey_get_private',
        'openssl_pkey_get_details',
        'sodium_crypto_sign_verify_detached',
        'random_bytes',
        'random_int',
        'base64_encode',
        'base64_decode',
    ]);

// Only crypto's PUBLIC surface is ours to use: whatever crypto tags @internal
// today or tomorrow must never be imported here, so an internal refactor of
// crypto can never break passkeys.
it('imports no crypto class tagged @internal', function (): void {
    $cryptoSrc = realpath(__DIR__.'/../vendor/roundly-consulting/crypto-for-laravel/src');

    expect($cryptoSrc)->toBeString();

    /** @var list<string> $internal */
    $internal = [];

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator((string) $cryptoSrc, FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $contents = (string) file_get_contents($file->getPathname());

        if (! str_contains($contents, '@internal')) {
            continue;
        }

        if (preg_match('/^namespace\s+([^;]+);/m', $contents, $namespace) === 1) {
            $internal[] = trim($namespace[1]).'\\'.$file->getBasename('.php');
        }
    }

    // If crypto ever stopped tagging anything @internal this guard would be
    // vacuous — prove it still has teeth, by name.
    expect($internal)->not->toBeEmpty()
        ->toContain('RoundlyConsulting\\Crypto\\Signature\\OpenSsl')
        ->toContain('RoundlyConsulting\\Crypto\\X509\\OpenSslX509');

    $offenders = [];

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__.'/../src', FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $contents = (string) file_get_contents($file->getPathname());

        foreach ($internal as $class) {
            if (str_contains($contents, 'use '.$class.';')) {
                $offenders[] = $file->getBasename().' → '.$class;
            }
        }
    }

    expect($offenders)->toBe([]);
});

/*
 * A CBOR attStmt's x5c carries RAW DER byte strings; Chain::fromX5c() decodes
 * base64, which is right for a JOSE x5c header and wrong here. A verifier built
 * on it would reject every genuine authenticator, so attestation code never
 * imports it — chains are built from Certificate::fromDer().
 */
it('never builds an attestation chain from the base64 x5c helper', function (): void {
    $offenders = [];

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__.'/../src/Attestation', FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        // Tokenised, so the prose warning ABOUT fromX5c in a docblock does not
        // itself trip the guard — only a real call would.
        foreach (token_get_all((string) file_get_contents($file->getPathname())) as $token) {
            if (is_array($token) && $token[0] === T_STRING && $token[1] === 'fromX5c') {
                $offenders[] = $file->getBasename();
            }
        }
    }

    expect($offenders)->toBe([]);
});

arch('src declares strict types')
    ->expect('RoundlyConsulting\Passkeys')
    ->toUseStrictTypes();

arch('actions are final')
    ->expect('RoundlyConsulting\Passkeys\Actions')
    ->toBeClasses()
    ->toBeFinal();

arch('data transfer objects are final and readonly')
    ->expect('RoundlyConsulting\Passkeys\DataTransferObjects')
    ->toBeFinal()
    ->toBeReadonly();

arch('enums are backed enums')
    ->expect('RoundlyConsulting\Passkeys\Enums')
    ->toBeEnums();

arch('exceptions extend the package base exception')
    ->expect('RoundlyConsulting\Passkeys\Exceptions')
    ->toExtend('RoundlyConsulting\Passkeys\Exceptions\PasskeyException')
    ->ignoring('RoundlyConsulting\Passkeys\Exceptions\PasskeyException');

arch('no debugging leftovers')
    ->expect(['dd', 'dump', 'ray', 'var_dump', 'print_r'])
    ->not->toBeUsed();
