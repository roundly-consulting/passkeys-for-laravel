<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifier;
use RoundlyConsulting\Passkeys\Attestation\NoneAttestationVerifier;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\Repositories\CacheChallengeRepository;

final class PasskeysServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/passkeys.php', 'passkeys');

        $this->app->singleton(PasskeyConfig::class, static function (): PasskeyConfig {
            $config = config('passkeys');
            $appUrl = config('app.url');

            return PasskeyConfig::fromArray(
                is_array($config) ? $config : [],
                is_string($appUrl) ? $appUrl : null,
            );
        });

        $this->app->singleton(ChallengeRepository::class, static function (Application $app): CacheChallengeRepository {
            return new CacheChallengeRepository(
                $app->make(CacheFactory::class),
                $app->make(PasskeyConfig::class)->challengeStore,
            );
        });

        $this->app->singleton(AttestationVerifier::class, static function (Application $app): NoneAttestationVerifier {
            return new NoneAttestationVerifier($app->make(PasskeyConfig::class)->rejectUnknownFmt);
        });

        $this->app->singleton(PasskeyManager::class);
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadTranslationsFrom(__DIR__.'/../resources/lang', 'passkeys');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/passkeys.php' => config_path('passkeys.php'),
            ], 'passkeys-config');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'passkeys-migrations');

            $this->publishes([
                __DIR__.'/../resources/lang' => $this->app->langPath('vendor/passkeys'),
            ], 'passkeys-translations');
        }
    }
}
