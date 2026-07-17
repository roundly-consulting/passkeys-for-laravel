<?php

declare(strict_types=1);

use RoundlyConsulting\PackageToolkit\Enums\DatabaseDriver;
use RoundlyConsulting\Passkeys\PasskeysServiceProvider;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * Passkeys ships one CREATE and one ALTER, and **zero foreign keys**: the credential's owner
 * is a `morphs('authenticatable')`, deliberately unconstrained so a host's user can live in
 * any table. That shape decides which halves of R and M apply below.
 */
$migrations = __DIR__.'/../../database/migrations';

/**
 * M — adopted, and NOT because of foreign keys.
 *
 * `MigrationGraph::assertRunnable()` checks two independent things, and only one is
 * FK-related. The other pins that a `Schema::table()` ALTER sorts at or after the CREATE of
 * the table it alters — approvals #2, the bug that half was built for. Passkeys ships exactly
 * that shape: `add_attestation_type_to_passkeys_table` must never sort before
 * `create_passkeys_table`.
 *
 * `foreignKeys: 0` is a live pin, not a formality: it forces a deliberate update the day an
 * edge arrives, and it proves the parse found the files rather than silently reading nothing.
 */
it('creates the passkeys table before the migration that alters it', function () use ($migrations): void {
    expect($migrations)->toHaveRunnableMigrationOrder(
        foreignKeys: 0,
        // Both migrations name their table `config('passkeys.table')`, so neither
        // `Schema::create` nor `Schema::table` takes a string literal. The graph refuses to
        // guess rather than silently reading the expression as a table name — declaring the
        // mapping is what lets it see that the CREATE and the ALTER target the SAME table,
        // which is the entire point of the ordering check here.
        // Single-quoted: a double-quoted key would interpolate `\$name` and silently look up
        // the wrong expression.
        tableResolvers: ['is_string($name) ? $name : \'passkeys\'' => 'passkeys'],
    );
});

/**
 * P — the publish-only guards. The fleet publishes migrations timestamped rather than
 * auto-loading them; doing both runs both copies and dies on a duplicate table (bug #5, on
 * three packages). `2` pins the file count so neither check can pass over an empty or
 * relocated directory.
 */
it('never auto-loads its migrations — the host publishes them', function (): void {
    expect(PasskeysServiceProvider::class)->toNotAutoLoadMigrations();
});

it('publishes its migrations timestamp-injected into the host', function (): void {
    expect(PasskeysServiceProvider::class)->toPublishMigrationsTimestamped('passkeys-migrations', 2);
});

/**
 * R — `toApplyOnConnection` only, and the omission of the negative control is deliberate
 * rather than an oversight.
 *
 * `toRejectBrokenOrderOnConnection` reverses the file list and requires the engine to refuse
 * it. With zero FK edges Postgres has nothing to refuse — the reversed order would simply
 * ALTER a table that does not exist yet, which it does reject, but the assertion's premise is
 * an FK graph, and the credits row proved that on a 0-FK package the control fails by design.
 * That is the assertion working correctly against a shape it does not fit, not a defect and
 * not a reason to weaken it.
 *
 * `migrations: 2` pins the count, and the assertion fails hard if a set "applies cleanly"
 * while creating no tables — an empty `up()` would otherwise pass and prove nothing.
 */
it('applies the published order cleanly on postgres', function () use ($migrations): void {
    expect($migrations)->toApplyOnConnection('pgsql', migrations: 2);
})->skip(fn (): bool => ! test()->connectionAvailable('pgsql'), 'pgsql connection not available');

/**
 * The driver-truth pin: the env-declared driver against what the connection itself answers.
 * It makes a lying pgsql leg impossible — a base case decapitated by an un-parented
 * `defineEnvironment()` override goes red here instead of quietly running SQLite and
 * reporting itself green.
 */
it('runs on the driver the environment declared', function (): void {
    expect(DatabaseDriver::current())->toBe(DatabaseDriver::from(DriverMatrix::driver()));
});
