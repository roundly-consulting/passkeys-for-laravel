<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use RoundlyConsulting\Crypto\CryptoServiceProvider;
use RoundlyConsulting\Passkeys\PasskeysServiceProvider;

abstract class TestCase extends Orchestra
{
    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        // crypto-for-laravel auto-registers in a host app; register it explicitly
        // here so the ceremonies run against its real container bindings.
        return [CryptoServiceProvider::class, PasskeysServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('app.url', 'https://example.com');
        $app['config']->set('passkeys.rp.id', 'example.com');
        $app['config']->set('passkeys.rp.name', 'Example');
        $app['config']->set('passkeys.origins', ['https://example.com']);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        $this->beforeApplicationDestroyed(function (): void {
            Schema::dropIfExists('users');
        });

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->string('passkey_user_handle')->nullable();
            $table->timestamps();
        });
    }
}
