<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Passkeys\PasskeysServiceProvider;
use RoundlyConsulting\Passkeys\Tests\Fixtures\PublishSandboxTestCase;

/**
 * Publishing runs against a throwaway database/ ({@see PublishSandboxTestCase}), never the
 * testbench skeleton whose `database/migrations` every parallel process migrates.
 */
it('publishes into the sandbox, never the shared skeleton', function (): void {
    $destinations = array_values(ServiceProvider::pathsToPublish(PasskeysServiceProvider::class, 'passkeys-migrations'));

    expect(database_path('migrations'))->toContain('passkeys-publish-')
        ->and($destinations)->toHaveCount(2)
        ->each->toStartWith(database_path('migrations').'/');
});

it('publishes each migration into the host timestamped', function (): void {
    $sources = glob(__DIR__.'/../../database/migrations/*.php') ?: [];

    expect($sources)->toHaveCount(2);

    Artisan::call('vendor:publish', ['--tag' => 'passkeys-migrations', '--force' => true]);

    $create = File::glob(database_path('migrations/*_create_passkeys_table.php'));
    $alter = File::glob(database_path('migrations/*_add_attestation_type_to_passkeys_table.php'));

    expect($create)->toHaveCount(1)
        ->and($alter)->toHaveCount(1)
        ->and(basename((string) $create[0]))->toMatch('/^\d{4}_\d{2}_\d{2}_\d{6}_create_passkeys_table\.php$/')
        ->and(basename((string) $alter[0]))->toMatch('/^\d{4}_\d{2}_\d{2}_\d{6}_add_attestation_type_to_passkeys_table\.php$/')
        // The ALTER must sort AFTER the CREATE once published, or a fresh host cannot migrate.
        ->and(basename((string) $alter[0]))->toBeGreaterThan(basename((string) $create[0]));
});
