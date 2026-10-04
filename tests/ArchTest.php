<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Exceptions\PasskeyException;
use RoundlyConsulting\Passkeys\Models\Passkey;
use RoundlyConsulting\Passkeys\UserPasskeys;
use RoundlyConsulting\Testing\Arch\ArchPresets;

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
        'Throwable',
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

/*
|--------------------------------------------------------------------------
| The shared presets
|--------------------------------------------------------------------------
|
| These replace the generic rules every package needs. The bespoke rules above
| are KEPT: the vendor-root guard, the crypto-primitive ban, the @internal-import
| guard and the x5c guard have no preset equivalent and encode this package's own
| independence and correctness decisions.
|
| Note the deliberate overlap: `noLocalCryptoPrimitives` and the hand-written ban
| above both police re-implemented primitives. The local list is STRICTER (it also
| bans openssl_*, sodium_*, random_*, base64_*, and `hash_equals`) and it stays
| authoritative. `hash_equals` was removed from the shared preset — the argument
| being that `->ignoring()` is class-scoped, so one correct call blinds a whole
| class to the other primitives — but that argument is about the shared list, not
| about this package, which routes constant-time comparison through crypto's
| wrapper and exempts nothing. Leaving the local ban intact is a crypto policy
| decision and is not this row's to reverse.
*/
ArchPresets::strictTypes('RoundlyConsulting\Passkeys');

/**
 * Exempt from finality, each deliberately (through `$ignoring`, so a stale entry fails):
 *  - Passkey — `passkeys.model` invites a host subclass; `final` is a PHP fatal the moment a
 *    host uses the documented seam. Pinned positively below.
 *  - PasskeyException — the base every passkeys error extends, so a host can catch the whole
 *    surface with one type.
 *  - UserPasskeys — the `Passkeys::for($user)` handle; `Passkeys::fake()` returns the recording
 *    subclass `Testing\RecordingUserPasskeys`, so every call through the facade or the model
 *    verbs is seen by the fake.
 */
ArchPresets::finalByDefault('RoundlyConsulting\Passkeys', [
    Passkey::class,
    PasskeyException::class,
    UserPasskeys::class,
]);

/**
 * `Models\Passkey` and the `InteractsWithPasskeys` verbs reach behaviour through
 * `Passkeys::for($this)` — never an action — so the fake sees every call.
 */
ArchPresets::modelsGoThroughTheFacade('RoundlyConsulting\Passkeys');

/**
 * The counter-weight, and the fleet's 7×-shipped fatal: `final` on a config-swappable model.
 * Also pins that `passkeys.model` really defaults to the packaged model, so the seam cannot
 * rot in the other direction either.
 */
ArchPresets::swappableModelsAreNotFinal([
    Passkey::class => 'passkeys.model',
]);

/**
 * `passkeys.model` resolves through the PasskeyModel seam in Support. Adopted on the
 * pre-classified rule (Swap? > 0): passkeys has the shape the preset targets — a real
 * Eloquent model behind a `*_model`-style key, every call site going through the seam.
 */
ArchPresets::modelsResolveThroughSeam(__DIR__.'/../src', 'Support', ['passkeys.model']);

/**
 * The morph-key seam, guarded. The passkeys table reaches its polymorphic subject column
 * through `morphKey($name, KeyType::fromConfig('passkeys.key_type'))`, never a raw
 * `$table->morphs()`, so a uuid/ulid host keys the credential owner coherently — a hardcoded
 * bigint id breaks those hosts on Postgres, and SQLite type affinity hides it. This pin reds if
 * a future migration reintroduces a raw morph and bypasses the seam.
 */
ArchPresets::morphColumnsUseTheSeam(__DIR__.'/../database/migrations');

/**
 * The Dependency Policy as a test. No `alsoAllow`: passkeys' `require` ships only
 * php/ext-json/illuminate/roundly, and the workflow installs test tooling with `--dev`. If
 * this goes red the graph is wrong — never widen the allow-list to quiet it.
 */
ArchPresets::runtimeRequireIsWhitelisted(__DIR__.'/../composer.json');

ArchPresets::noDebuggingLeftovers();
