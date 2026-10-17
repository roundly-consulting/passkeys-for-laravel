<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests;

use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Crypto\CryptoServiceProvider;
use RoundlyConsulting\Passkeys\PasskeysServiceProvider;
use RoundlyConsulting\Testing\PackageTestCase;

abstract class TestCase extends PackageTestCase
{
    /**
     * crypto-for-laravel auto-registers in a host app; the suite lists it explicitly so the
     * ceremonies run against its real container bindings rather than a fiction.
     *
     * @return list<class-string<ServiceProvider>>
     */
    protected function packageProviders(): array
    {
        return [CryptoServiceProvider::class, PasskeysServiceProvider::class];
    }

    /**
     * The two passkeys migrations, named by provider class (never by filename), then the
     * fixtures: the host-owned `users` and `clients` tables the credentials hang off.
     *
     * @return list<class-string<ServiceProvider>|string>
     */
    protected function migrationSources(): array
    {
        return [PasskeysServiceProvider::class, __DIR__.'/Fixtures/migrations'];
    }

    /**
     * Migrate once per worker and reset only the data between tests. The migrations read
     * config alone (table name, key type, handle column), which the schema signature covers.
     */
    protected function keepsMigratedSchema(): bool
    {
        return true;
    }

    /**
     * @return array<string, mixed>
     */
    protected function configBeforeBoot(): array
    {
        return [
            'app.url' => 'https://example.com',
            'passkeys.rp.id' => 'example.com',
            'passkeys.rp.name' => 'Example',
            'passkeys.origins' => ['https://example.com'],
        ];
    }
}
