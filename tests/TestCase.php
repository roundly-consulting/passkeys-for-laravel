<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
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
     * The two passkeys migrations, named by provider class (never by filename).
     *
     * @return list<class-string<ServiceProvider>|string>
     */
    protected function migrationSources(): array
    {
        return [PasskeysServiceProvider::class];
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

    /**
     * The host-owned `users` and `clients` tables the credentials hang off. They stand in
     * for tables a host owns — including the opaque handle column
     * `passkeys.user.handle_column` names — so they are built here rather than shipped.
     *
     * The explicit `dropIfExists` the previous base case registered is gone: PackageTestCase
     * resets by dropping every table between tests, so nothing survives to clean up.
     */
    protected function defineDatabaseMigrations(): void
    {
        parent::defineDatabaseMigrations();

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->string('passkey_user_handle')->nullable();
            $table->timestamps();
        });

        // A second guard's account table, so ownership checks can prove the owner TYPE
        // matters when two owners share a key.
        Schema::create('clients', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->string('passkey_user_handle')->nullable();
            $table->timestamps();
        });
    }
}
