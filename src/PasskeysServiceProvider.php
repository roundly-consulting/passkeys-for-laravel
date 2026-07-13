<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Passkeys\Attestation\AttestationAnchors;
use RoundlyConsulting\Passkeys\Attestation\AttestationGate;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifier;
use RoundlyConsulting\Passkeys\Attestation\AttestationVerifierRegistry;
use RoundlyConsulting\Passkeys\Attestation\NoneAttestationVerifier;
use RoundlyConsulting\Passkeys\Attestation\PackedAttestationVerifier;
use RoundlyConsulting\Passkeys\Contracts\ChallengeRepository;
use RoundlyConsulting\Passkeys\Contracts\PasskeyService;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\Repositories\CacheChallengeRepository;
use RoundlyConsulting\Passkeys\Support\CredentialCrypto;

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

        $this->app->singleton(AttestationVerifierRegistry::class, static function (Application $app): AttestationVerifierRegistry {
            return new AttestationVerifierRegistry([
                'none' => new NoneAttestationVerifier,
                'packed' => new PackedAttestationVerifier($app->make(CredentialCrypto::class)),
            ]);
        });

        $this->app->singleton(AttestationAnchors::class, static function (Application $app): AttestationAnchors {
            return new AttestationAnchors($app->make(PasskeyConfig::class));
        });

        // The ceremony is bound to the trust POLICY, never to a format verifier:
        // the gate is what decides, and the registry is what it delegates maths to.
        $this->app->singleton(AttestationVerifier::class, static function (Application $app): AttestationGate {
            return new AttestationGate(
                $app->make(AttestationVerifierRegistry::class),
                $app->make(AttestationAnchors::class),
                $app->make(PasskeyConfig::class),
            );
        });

        $this->app->singleton(PasskeyManager::class);
        $this->app->singleton(
            PasskeyService::class,
            static fn (Application $app): PasskeyManager => $app->make(PasskeyManager::class),
        );
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
