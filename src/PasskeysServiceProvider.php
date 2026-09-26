<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\ColumnDefinition;
use RoundlyConsulting\PackageToolkit\Concerns\RegistersBlueprintMacros;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;
use RoundlyConsulting\Passkeys\Attestation\AppleAttestationVerifier;
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
use RoundlyConsulting\Passkeys\Support\PasskeyModel;
use RoundlyConsulting\Passkeys\Support\UserHandleColumn;

final class PasskeysServiceProvider extends PackageServiceProvider
{
    use RegistersBlueprintMacros;

    public function configurePackage(Package $package): void
    {
        // 'passkeys' is the CONFIG handle: it keeps config/passkeys.php, the
        // passkeys-config / -migrations / -translations tags and the `passkeys::`
        // translation namespace byte-identical to the hand-wired provider.
        $package
            ->name('passkeys')
            ->hasConfigFile()
            ->hasMigrations()
            ->hasTranslations()
            ->contributesToAbout(fn (): array => $this->aboutData());
    }

    public function register(): void
    {
        parent::register();

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
                'apple' => new AppleAttestationVerifier,
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
        parent::boot();

        // The migration's key-type-aware authenticatable morph is a macro, so it must
        // exist before a host runs `php artisan migrate`.
        $this->registerBlueprintMacros();
        $this->registerUserHandleMacro();
    }

    /**
     * `$table->passkeyUserHandle()` — the host-owned handle column on any account
     * table: nullable (the handle is minted lazily on first use) and unique (it
     * resolves exactly one account during a discoverable login).
     */
    private function registerUserHandleMacro(): void
    {
        if (Blueprint::hasMacro('passkeyUserHandle')) {
            return;
        }

        Blueprint::macro('passkeyUserHandle', function (): ColumnDefinition {
            /** @var Blueprint $this */
            return $this->string(UserHandleColumn::name())->nullable()->unique();
        });
    }

    /**
     * The `php artisan about` payload — the strictest secret discipline in the fleet.
     *
     * A relying party's configuration IS its credential surface: the RP ID and the
     * origin allow-list name the host's authentication domain, the anchor paths point
     * at its trust store, and the AAGUID allow-list names the exact authenticator
     * models it will admit. None of them are rendered. What ships instead is the
     * security POSTURE (trust ladder, conveyance, verification requirements), counts,
     * TTLs, and SET/MISSING presence — enough to diagnose a misconfiguration, never
     * enough to reconstruct one.
     *
     * @return array<string, string>
     */
    private function aboutData(): array
    {
        $anchorPaths = $this->configArray('passkeys.attestation_anchors.paths');
        $aaguids = $this->configArray('passkeys.aaguids.allowed');

        return [
            'Model' => class_basename(PasskeyModel::class()),
            'Relying party' => 'id '.$this->presence(config('passkeys.rp.id')).', name '.$this->presence(config('passkeys.rp.name')),
            'Origins' => $this->countOf('passkeys.origins', 'origin').', cross-origin '.$this->toggle('passkeys.allow_cross_origin'),
            'Algorithms' => $this->countOf('passkeys.algorithms', 'algorithm'),
            'User verification' => $this->stringOr('passkeys.user_verification', 'required'),
            'Resident key' => $this->stringOr('passkeys.resident_key', 'required'),
            'Ceremony timeout' => $this->intOr('passkeys.timeout_ms', 60_000).'ms',
            'Challenge' => $this->intOr('passkeys.challenge.bytes', 32).' bytes, TTL '
                .$this->intOr('passkeys.challenge.ttl', 60).'s, store '
                .(is_string(config('passkeys.challenge.store')) ? 'CUSTOM' : 'DEFAULT'),
            'Attestation' => 'conveyance '.$this->stringOr('passkeys.attestation', 'none')
                .', trust '.$this->stringOr('passkeys.attestation_trust', 'ignore')
                .', unknown formats '.(config('passkeys.reject_unknown_fmt') === true ? 'REJECTED' : 'ACCEPTED'),
            'Trust anchors' => 'bundled roots '.($this->boolOr('passkeys.attestation_anchors.defaults', true) ? 'ON' : 'OFF')
                .', '.count($anchorPaths).' host path(s), skew '
                .$this->intOr('passkeys.attestation_clock_skew', 60).'s',
            'AAGUID allow-list' => $aaguids === [] ? 'ANY' : count($aaguids).' allowed',
            'Sign-count policy' => $this->stringOr('passkeys.sign_count_policy', 'flag'),
            'User handle' => 'column '.$this->presence(config('passkeys.user.handle_column')).', '
                .$this->intOr('passkeys.user.handle_bytes', 32).' bytes',
        ];
    }

    private function presence(mixed $value): string
    {
        return is_string($value) && $value !== '' ? 'SET' : 'MISSING';
    }

    private function toggle(string $key): string
    {
        return config($key) === true ? 'ON' : 'OFF';
    }

    private function boolOr(string $key, bool $default): bool
    {
        $value = config($key);

        return is_bool($value) ? $value : $default;
    }

    private function stringOr(string $key, string $default): string
    {
        $value = config($key);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    private function intOr(string $key, int $default): int
    {
        $value = config($key);

        return is_numeric($value) ? (int) $value : $default;
    }

    private function countOf(string $key, string $noun): string
    {
        return count($this->configArray($key)).' '.$noun.'(s)';
    }

    /** @return array<array-key, mixed> */
    private function configArray(string $key): array
    {
        $value = config($key);

        return is_array($value) ? $value : [];
    }
}
