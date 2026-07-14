<?php

declare(strict_types=1);

use Illuminate\Support\Arr;

/**
 * The config contract, pinned in BOTH directions.
 *
 * A key the code reads but the package never ships is unreachable — the feature is
 * configurable only in theory. A key the package ships but no code reads is a documented
 * feature that silently does nothing (this package shipped exactly that: `passkeys.model`
 * was documented as the model seam and read nowhere). Both have shipped in this fleet;
 * neither can ship again from here.
 *
 * Everything is scraped from real string *tokens*, never the raw text: a key named only in
 * a comment or a docblock is not a read, and counting it would let this test pass over a
 * key nothing executes.
 */

/** @return list<string> */
function passkeysSourceFiles(bool $withProvider = true): array
{
    $files = [];

    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__.'/../../src'));

    foreach ($iterator as $file) {
        if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
            continue;
        }

        if (! $withProvider && str_ends_with($file->getPathname(), 'PasskeysServiceProvider.php')) {
            continue;
        }

        $files[] = $file->getPathname();
    }

    foreach (glob(__DIR__.'/../../database/migrations/*.php') ?: [] as $migration) {
        $files[] = $migration;
    }

    return $files;
}

/**
 * Full-path reads: a `config('passkeys.…')` literal, or a dotted sub-path literal handed to
 * a reader that prefixes it (`InteractsWithPasskeys::passkeyConfigString('user.name_attribute')`).
 *
 * @param  list<string>  $files
 * @return list<string>
 */
function passkeysPathReads(array $files): array
{
    $keys = [];

    foreach ($files as $file) {
        foreach (token_get_all((string) file_get_contents($file)) as $token) {
            if (! is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
                continue;
            }

            $literal = trim($token[1], "'\"");

            if (preg_match('/^passkeys\.[a-z0-9_.]+$/', $literal) === 1) {
                $keys[] = $literal;
            }

            // A section-relative path handed to a config reader that prefixes `passkeys.`.
            if (preg_match('/^(rp|challenge|user|aaguids|attestation_anchors)\.[a-z0-9_.]+$/', $literal) === 1) {
                $keys[] = 'passkeys.'.$literal;
            }
        }
    }

    return $keys;
}

/**
 * The typed config DTO is handed the whole `passkeys` array and reads it by array offset —
 * `$config['timeout_ms']`, `$challenge['ttl']`, `$rp['id']`. Those are the package's real
 * reads for almost every key, so they are scraped as `$variable['literal']` token triples
 * and mapped back onto the config path each variable holds.
 *
 * @return list<string>
 */
function passkeysDtoReads(): array
{
    // The section each local variable in PasskeyConfig::fromArray() holds.
    $sections = [
        '$config' => 'passkeys',
        '$rp' => 'passkeys.rp',
        '$challenge' => 'passkeys.challenge',
        '$user' => 'passkeys.user',
        '$anchors' => 'passkeys.attestation_anchors',
        '$aaguids' => 'passkeys.aaguids',
    ];

    $tokens = array_values(array_filter(
        token_get_all((string) file_get_contents(__DIR__.'/../../src/DataTransferObjects/PasskeyConfig.php')),
        fn (array|string $token): bool => ! is_array($token) || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
    ));

    $keys = [];

    foreach ($tokens as $index => $token) {
        if (! is_array($token) || $token[0] !== T_VARIABLE || ! isset($sections[$token[1]])) {
            continue;
        }

        $open = $tokens[$index + 1] ?? null;
        $literal = $tokens[$index + 2] ?? null;
        $close = $tokens[$index + 3] ?? null;

        if ($open !== '[' || $close !== ']' || ! is_array($literal) || $literal[0] !== T_CONSTANT_ENCAPSED_STRING) {
            continue;
        }

        $keys[] = $sections[$token[1]].'.'.trim($literal[1], "'\"");
    }

    return $keys;
}

/**
 * Every leaf key in the shipped config file. Descends into associative sections and stops at
 * scalars and list values (`origins`, `algorithms`, `aaguids.allowed`, …).
 *
 * @param  array<array-key, mixed>  $config
 * @return list<string>
 */
function passkeysConfigLeaves(array $config, string $prefix = 'passkeys'): array
{
    $leaves = [];

    foreach ($config as $key => $value) {
        $path = $prefix.'.'.$key;

        if (is_array($value) && $value !== [] && ! array_is_list($value)) {
            $leaves = [...$leaves, ...passkeysConfigLeaves($value, $path)];

            continue;
        }

        $leaves[] = $path;
    }

    return $leaves;
}

it('ships every config key the source reads', function (): void {
    $shipped = require __DIR__.'/../../config/passkeys.php';

    // The provider IS included here: a key it reads must still exist.
    $read = array_unique([...passkeysPathReads(passkeysSourceFiles()), ...passkeysDtoReads()]);

    expect($read)->not->toBeEmpty();

    $missing = array_values(array_filter(
        $read,
        fn (string $key): bool => ! Arr::has(['passkeys' => $shipped], $key),
    ));

    expect($missing)->toBe([]);
});

it('reads every config key it ships', function (): void {
    $shipped = require __DIR__.'/../../config/passkeys.php';

    // The provider is EXCLUDED here: its `about` payload RENDERS config, it does not apply
    // it. Counting a rendered key as a read would let a dead key pass this pin vacuously.
    $read = array_unique([...passkeysPathReads(passkeysSourceFiles(withProvider: false)), ...passkeysDtoReads()]);

    $leaves = passkeysConfigLeaves($shipped);

    expect($leaves)->not->toBeEmpty();

    $dead = array_values(array_filter(
        $leaves,
        fn (string $key): bool => ! in_array($key, $read, true),
    ));

    expect($dead)->toBe([]);
});

it('resolves the passkey model only through the model seam', function (): void {
    $offenders = [];

    foreach (passkeysSourceFiles() as $file) {
        if (str_ends_with($file, 'Support/PasskeyModel.php')) {
            continue;
        }

        if (str_contains((string) file_get_contents($file), "'passkeys.model'")) {
            $offenders[] = basename($file);
        }
    }

    expect($offenders)->toBe([]);
});
