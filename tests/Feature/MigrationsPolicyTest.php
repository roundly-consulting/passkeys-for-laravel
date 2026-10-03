<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;

/**
 * Migrations are PUBLISH-ONLY (fleet policy): the package never loads them, the host
 * publishes them and then runs `php artisan migrate`. The publish itself is proven in
 * `tests/Publish/PublishMigrationsTest.php`, against a sandboxed database/.
 */
it('never auto-loads its migrations', function (): void {
    $packaged = realpath(__DIR__.'/../../database/migrations');

    $loaded = array_map(
        fn (string $path): string => (string) realpath($path),
        app('migrator')->paths(),
    );

    expect($loaded)->not->toContain($packaged);
});

/**
 * The structural, engine-independent order pin. SQLite silently accepts a table that
 * references a missing parent (and an ALTER is the only ordering constraint this package
 * has), so reading the SOURCES is the only check that proves the publish order is
 * runnable on MySQL/Postgres. Parses both foreign-key forms Laravel offers —
 * `->constrained('parent')` / `foreignId` and the long-hand `->references('id')->on('parent')`
 * — and requires every ALTER to follow its table's CREATE.
 */
it('creates every table before the migration that references it', function (): void {
    $sources = glob(__DIR__.'/../../database/migrations/*.php') ?: [];
    sort($sources);

    expect($sources)->not->toBeEmpty();

    // The passkeys table name is config-driven, so Schema::create() takes a variable.
    $configured = is_string($name = config('passkeys.table')) ? $name : 'passkeys';

    /** @var array<string, int> $createdAt */
    $createdAt = [];
    /** @var list<array{parent: string, position: int}> $edges */
    $edges = [];
    /** @var list<array{table: string, position: int}> $alters */
    $alters = [];

    foreach ($sources as $position => $source) {
        $body = (string) file_get_contents($source);

        preg_match_all("/Schema::create\(\s*(?:'([a-z0-9_]+)'|[^,]+)/", $body, $creates);

        foreach ($creates[1] as $table) {
            $createdAt[$table === '' ? $configured : $table] ??= $position;
        }

        preg_match_all("/Schema::table\(\s*(?:'([a-z0-9_]+)'|[^,]+)/", $body, $tables);

        foreach ($tables[1] as $table) {
            $alters[] = ['table' => $table === '' ? $configured : $table, 'position' => $position];
        }

        preg_match_all("/->(?:constrained|on)\('([a-z0-9_]+)'\)/i", $body, $parents);

        foreach ($parents[1] as $parent) {
            $edges[] = ['parent' => $parent, 'position' => $position];
        }
    }

    expect($createdAt)->toHaveKey($configured)
        ->and($alters)->not->toBeEmpty();

    foreach ($edges as $edge) {
        expect($createdAt)->toHaveKey($edge['parent'])
            ->and($createdAt[$edge['parent']])->toBeLessThanOrEqual($edge['position']);
    }

    foreach ($alters as $alter) {
        expect($createdAt)->toHaveKey($alter['table'])
            ->and($createdAt[$alter['table']])->toBeLessThanOrEqual($alter['position']);
    }
});

/**
 * `passkeys.table` is documented as the way to rename the credential table, and the model
 * reads it — so the migration has to honour it too, or a host that renames the table gets a
 * `passkeys` table its model never looks at.
 */
it('creates the table the host configured', function (): void {
    config()->set('passkeys.table', 'acme_credentials');

    foreach (glob(__DIR__.'/../../database/migrations/*.php') ?: [] as $source) {
        $migration = require $source;
        $migration->up();
    }

    expect(Schema::hasTable('acme_credentials'))->toBeTrue()
        ->and(Schema::hasColumn('acme_credentials', 'credential_id_hash'))->toBeTrue()
        // The ALTER lands on the configured table too, not on the packaged default.
        ->and(Schema::hasColumn('acme_credentials', 'attestation_type'))->toBeTrue();

    Schema::dropIfExists('acme_credentials');
});
