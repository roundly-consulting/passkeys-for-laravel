<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\PackageToolkit\Exceptions\InvalidConfigurationException;
use RoundlyConsulting\Testing\Database\DriverMatrix;

function runPasskeysMigration(): void
{
    $migration = require __DIR__.'/../../database/migrations/2024_01_01_000001_create_passkeys_table.php';
    $migration->up();
}

function passkeysCreateTable(string $table): string
{
    /** @var list<object{sql: string|null}> $rows */
    $rows = DB::select('select sql from sqlite_master where type = ? and name = ?', ['table', $table]);

    return (string) ($rows[0]->sql ?? '');
}

/** @return array{type: string, nullable: string} */
function passkeysPgColumn(string $table, string $column): array
{
    /** @var list<object{data_type: string, character_maximum_length: int|null, is_nullable: string}> $rows */
    $rows = DB::select(
        'select data_type, character_maximum_length, is_nullable from information_schema.columns where table_name = ? and column_name = ?',
        [$table, $column],
    );

    $row = $rows[0] ?? null;

    if ($row === null) {
        return ['type' => 'MISSING', 'nullable' => 'MISSING'];
    }

    $type = $row->character_maximum_length === null
        ? $row->data_type
        : $row->data_type.'('.$row->character_maximum_length.')';

    return ['type' => $type, 'nullable' => $row->is_nullable];
}

$sqliteOnly = fn (): bool => DriverMatrix::driver() !== 'sqlite';
$pgsqlOnly = fn (): bool => DriverMatrix::driver() !== 'pgsql';

it('creates the polymorphic authenticatable column', function (): void {
    expect(Schema::hasColumns('passkeys', ['authenticatable_type', 'authenticatable_id']))->toBeTrue();
});

/**
 * The core P1 safety property: `morphKey($n, BigInt, nullable: false)` IS `morphs($n)`.
 * The authenticatable morph is NOT nullable — a passkey always belongs to someone — so the
 * reference is raw `morphs()`, and a wrong nullability would surface as a string difference.
 */
it('emits a bigint authenticatable morph byte-identical to raw morphs()', function (): void {
    config()->set('passkeys.key_type', 'bigint');
    config()->set('passkeys.table', 'kt_ident_passkeys');

    Schema::dropIfExists('kt_ident_passkeys');
    runPasskeysMigration();

    Schema::dropIfExists('authenticatable_raw_ref');
    Schema::create('authenticatable_raw_ref', function (Blueprint $table): void {
        $table->id();
        $table->morphs('authenticatable');
    });

    expect(passkeysCreateTable('kt_ident_passkeys'))->toContain('"authenticatable_type" varchar not null, "authenticatable_id" integer not null')
        ->and(passkeysCreateTable('authenticatable_raw_ref'))->toContain('"authenticatable_type" varchar not null, "authenticatable_id" integer not null');

    Schema::dropIfExists('kt_ident_passkeys');
    Schema::dropIfExists('authenticatable_raw_ref');
})->skip($sqliteOnly, 'sqlite_master is the sqlite catalog')->group('sqlite');

/**
 * The headline of P1: a uuid/ulid host gets uuid/ulid authenticatable columns; bigint stays
 * bigint. Postgres tells the three apart; the morph stays NOT NULL, matching raw `morphs()`.
 */
it('renders each configured key type as a distinct real column type', function (string $keyType, string $expected): void {
    config()->set('passkeys.key_type', $keyType);
    config()->set('passkeys.table', 'kt_passkeys');

    Schema::dropIfExists('kt_passkeys');
    runPasskeysMigration();

    expect(passkeysPgColumn('kt_passkeys', 'authenticatable_id'))->toBe(['type' => $expected, 'nullable' => 'NO'])
        ->and(passkeysPgColumn('kt_passkeys', 'authenticatable_type')['type'])->toBe('character varying(255)');

    Schema::dropIfExists('kt_passkeys');
})->with([
    'bigint' => ['bigint', 'bigint'],
    'uuid' => ['uuid', 'uuid'],
    'ulid' => ['ulid', 'character(26)'],
])->skip($pgsqlOnly, 'needs the postgres catalog to tell the key types apart')->group('pgsql');

it('refuses to migrate on an unrecognized key type instead of falling back to bigint', function (): void {
    config()->set('passkeys.key_type', 'nonsense');
    config()->set('passkeys.table', 'fallback_passkeys');

    Schema::dropIfExists('fallback_passkeys');

    // A typo in a host's config must stop the migration, never silently build bigint
    // columns for a uuid/ulid-keyed host.
    expect(function (): void {
        runPasskeysMigration();
    })->toThrow(InvalidConfigurationException::class, 'Configuration value [passkeys.key_type] must be one of [bigint, uuid, ulid] (case-insensitive), [nonsense] given.');

    Schema::dropIfExists('fallback_passkeys');
});
