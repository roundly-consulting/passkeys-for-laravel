<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\DataTransferObjects;

use RoundlyConsulting\Crypto\Cose\CoseAlgorithm;
use RoundlyConsulting\PackageToolkit\Support\Config;
use RoundlyConsulting\PackageToolkit\Support\ConfigValidator;
use RoundlyConsulting\Passkeys\Enums\AttestationConveyance;
use RoundlyConsulting\Passkeys\Enums\AttestationTrust;
use RoundlyConsulting\Passkeys\Enums\ResidentKey;
use RoundlyConsulting\Passkeys\Enums\SignCountPolicy;
use RoundlyConsulting\Passkeys\Enums\UserVerification;
use RoundlyConsulting\Passkeys\Exceptions\InvalidConfiguration;

/**
 * A typed, validated view over `config/passkeys.php`, also parsed by the
 * service provider at boot so a misconfiguration fails the app there. Security-critical
 * values (rp.id, origins) are resolved eagerly but only *enforced* when a
 * ceremony actually needs them, so the package boots with zero host configuration.
 */
final readonly class PasskeyConfig
{
    /**
     * The COSE algorithms this relying party will register and verify.
     *
     * crypto-for-laravel's COSE registry is deliberately wider than this (it also
     * carries ES384 and ES512). A relying party accepts only what it has vetted,
     * so the configured list is narrowed back to exactly these three — the set
     * WebAuthn authenticators actually mint — and anything else is rejected at
     * config-parse time rather than silently accepted through the shared enum.
     *
     * @var list<CoseAlgorithm>
     */
    public const array SUPPORTED_ALGORITHMS = [
        CoseAlgorithm::ES256,
        CoseAlgorithm::RS256,
        CoseAlgorithm::EdDSA,
    ];

    /**
     * The widest clock-skew leeway a host may grant an attestation certificate's
     * validity window. An hour is already generous for a wall clock; more is a
     * typo, not a policy.
     */
    public const int MAX_ATTESTATION_CLOCK_SKEW = 3600;

    /**
     * @param  list<string>  $origins
     * @param  list<int>  $algorithms
     * @param  array<string, list<string>>  $attestationAnchorPaths  format => absolute PEM paths
     * @param  list<string>  $allowedAaguids
     */
    public function __construct(
        public ?string $rpId,
        public string $rpName,
        public array $origins,
        public bool $allowCrossOrigin,
        public array $algorithms,
        public int $timeoutMs,
        public AttestationConveyance $attestation,
        public UserVerification $userVerification,
        public ResidentKey $residentKey,
        public ?string $challengeStore,
        public int $challengeTtl,
        public int $challengeBytes,
        public SignCountPolicy $signCountPolicy,
        public AttestationTrust $attestationTrust,
        public bool $rejectUnknownFmt,
        public bool $attestationAnchorDefaults,
        public array $attestationAnchorPaths,
        public int $attestationClockSkew,
        public array $allowedAaguids,
        public string $userHandleColumn,
        public int $userHandleBytes,
        public string $userNameAttribute,
        public string $userDisplayNameAttribute,
    ) {}

    /**
     * Every value is read strictly: an absent (null) key takes its default, but a present
     * value of the wrong shape throws {@see InvalidConfiguration} naming the key — a typo'd
     * enum, a `'five'` timeout, a non-string origin or a non-list allow-list never silently
     * becomes the default (or, for an allow-list, "allow anything").
     *
     * @param  array<string, mixed>  $config
     *
     * @throws InvalidConfiguration
     */
    public static function fromArray(array $config, ?string $appUrl = null): self
    {
        $read = Config::for(['passkeys' => $config], InvalidConfiguration::class);

        $rpId = self::optionalString('rp.id', $config['rp']['id'] ?? null) ?? self::hostFromUrl($appUrl);

        $origins = self::stringList('origins', $config['origins'] ?? null);
        $algorithms = self::algorithms($config['algorithms'] ?? null);

        self::assertSupportedAlgorithms($algorithms);

        $attestationTrust = $read->enum('passkeys.attestation_trust', AttestationTrust::class, AttestationTrust::Ignore);
        $attestation = $read->enum('passkeys.attestation', AttestationConveyance::class, AttestationConveyance::None);

        // Demanding proof while telling authenticators not to attest would refuse
        // every registration, at ceremony time, for a reason the host cannot see.
        // One `if` at config-parse time instead.
        if ($attestationTrust !== AttestationTrust::Ignore && $attestation === AttestationConveyance::None) {
            throw InvalidConfiguration::attestationConveyanceMismatch($attestationTrust->value);
        }

        return new self(
            rpId: $rpId,
            rpName: self::string('rp.name', $config['rp']['name'] ?? null, 'Laravel'),
            origins: $origins,
            allowCrossOrigin: $read->boolean('passkeys.allow_cross_origin'),
            algorithms: $algorithms,
            timeoutMs: $read->integer('passkeys.timeout_ms', 60_000, min: 1),
            attestation: $attestation,
            userVerification: $read->enum('passkeys.user_verification', UserVerification::class, UserVerification::Required),
            residentKey: $read->enum('passkeys.resident_key', ResidentKey::class, ResidentKey::Required),
            challengeStore: self::optionalString('challenge.store', $config['challenge']['store'] ?? null),
            challengeTtl: $read->integer('passkeys.challenge.ttl', 60, min: 1),
            challengeBytes: $read->integer('passkeys.challenge.bytes', 32, min: 16),
            signCountPolicy: $read->enum('passkeys.sign_count_policy', SignCountPolicy::class, SignCountPolicy::Flag),
            attestationTrust: $attestationTrust,
            rejectUnknownFmt: $read->boolean('passkeys.reject_unknown_fmt'),
            attestationAnchorDefaults: $read->boolean('passkeys.attestation_anchors.defaults', true),
            attestationAnchorPaths: self::anchorPaths($config['attestation_anchors']['paths'] ?? null),
            attestationClockSkew: self::clockSkew($read),
            allowedAaguids: array_map(strtolower(...), self::stringList('aaguids.allowed', $config['aaguids']['allowed'] ?? null)),
            userHandleColumn: self::string('user.handle_column', $config['user']['handle_column'] ?? null, 'passkey_user_handle'),
            userHandleBytes: $read->integer('passkeys.user.handle_bytes', 32, min: 16, max: 64),
            userNameAttribute: self::string('user.name_attribute', $config['user']['name_attribute'] ?? null, 'email'),
            userDisplayNameAttribute: self::string('user.display_name_attribute', $config['user']['display_name_attribute'] ?? null, 'name'),
        );
    }

    /**
     * How long to keep a ceremony's challenge: `challenge.ttl`, but never less than the
     * timeout the options hand the browser (rounded up to whole seconds). A ceremony the
     * user finishes inside the promised window must not be refused as expired, whether
     * the longer timeout comes from config or from a per-call override.
     */
    public function challengeTtlFor(int $timeoutMs): int
    {
        return max($this->challengeTtl, (int) ceil($timeoutMs / 1000));
    }

    /**
     * @throws InvalidConfiguration
     */
    public function requireRpId(): string
    {
        if ($this->rpId === null || $this->rpId === '') {
            throw InvalidConfiguration::missingRpId();
        }

        return $this->rpId;
    }

    /**
     * @return list<string>
     *
     * @throws InvalidConfiguration
     */
    public function requireOrigins(): array
    {
        if ($this->origins === []) {
            throw InvalidConfiguration::emptyOrigins();
        }

        return $this->origins;
    }

    /**
     * The anchors configured for one format, or an empty list.
     *
     * @return list<string>
     */
    public function anchorPathsFor(string $format): array
    {
        return $this->attestationAnchorPaths[$format] ?? [];
    }

    /**
     * Host-supplied trust anchors, normalised to `format => list<path>`. A non-list
     * value, a non-string format or a blank/non-string path throws rather than being
     * dropped — a silently skipped anchor is a trust root the host thinks it set.
     *
     * @return array<string, list<string>>
     *
     * @throws InvalidConfiguration
     */
    private static function anchorPaths(mixed $paths): array
    {
        if ($paths === null) {
            return [];
        }

        if (! is_array($paths)) {
            throw InvalidConfiguration::invalidValue('attestation_anchors.paths', 'a map of format => list of PEM paths', $paths);
        }

        $normalised = [];

        foreach ($paths as $format => $configured) {
            if (! is_string($format)) {
                throw InvalidConfiguration::invalidValue('attestation_anchors.paths', 'keyed by attestation format', $format);
            }

            $files = self::stringList("attestation_anchors.paths.{$format}", $configured ?? []);

            if ($files !== []) {
                $normalised[$format] = $files;
            }
        }

        return $normalised;
    }

    /**
     * @throws InvalidConfiguration
     */
    private static function clockSkew(ConfigValidator $read): int
    {
        $seconds = $read->integer('passkeys.attestation_clock_skew', 60);

        if ($seconds < 0 || $seconds > self::MAX_ATTESTATION_CLOCK_SKEW) {
            throw InvalidConfiguration::invalidClockSkew((string) $seconds, self::MAX_ATTESTATION_CLOCK_SKEW);
        }

        return $seconds;
    }

    /**
     * The configured COSE algorithms: absent → ES256 + RS256. Each entry must be an
     * int (or a canonical integer string); an empty list or any other entry throws
     * rather than being dropped — dropping `'-8'` would quietly offer ES256/RS256.
     *
     * @return list<int>
     *
     * @throws InvalidConfiguration
     */
    private static function algorithms(mixed $configured): array
    {
        if ($configured === null) {
            return [CoseAlgorithm::ES256->value, CoseAlgorithm::RS256->value];
        }

        if (! is_array($configured) || $configured === []) {
            throw InvalidConfiguration::invalidValue('algorithms', 'a non-empty list of COSE algorithm identifiers', $configured);
        }

        $algorithms = [];

        foreach ($configured as $index => $algorithm) {
            $algorithms[] = Config::for(['passkeys.algorithms.'.$index => $algorithm], InvalidConfiguration::class)
                ->integer('passkeys.algorithms.'.$index, 0);
        }

        return $algorithms;
    }

    /**
     * A list of non-blank strings; `[]` when absent. A non-list, or any entry that is
     * not a non-blank string, throws — an allow-list must never silently shrink to
     * "allow anything".
     *
     * @return list<string>
     *
     * @throws InvalidConfiguration
     */
    private static function stringList(string $key, mixed $value): array
    {
        if ($value === null) {
            return [];
        }

        if (! is_array($value)) {
            throw InvalidConfiguration::invalidValue($key, 'a list of strings', $value);
        }

        $strings = [];

        foreach ($value as $item) {
            if (! is_string($item) || trim($item) === '') {
                throw InvalidConfiguration::invalidValue($key, 'a list of non-empty strings', $item);
            }

            $strings[] = $item;
        }

        return $strings;
    }

    /**
     * An optional string: null when absent or blank (an empty env value); a value that
     * is not a string throws.
     *
     * @throws InvalidConfiguration
     */
    private static function optionalString(string $key, mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw InvalidConfiguration::invalidValue($key, 'a string or null', $value);
        }

        return trim($value) === '' ? null : $value;
    }

    /**
     * A required string: `$default` only when absent; blank or non-string throws.
     *
     * @throws InvalidConfiguration
     */
    private static function string(string $key, mixed $value, string $default): string
    {
        $value ??= $default;

        if (! is_string($value) || trim($value) === '') {
            throw InvalidConfiguration::invalidValue($key, 'a non-empty string', $value);
        }

        return $value;
    }

    /**
     * Reject any configured COSE identifier outside {@see SUPPORTED_ALGORITHMS} —
     * including one crypto knows but this relying party does not — rather than
     * offering an algorithm the ceremony has never been vetted against.
     *
     * @param  list<int>  $algorithms
     *
     * @throws InvalidConfiguration
     */
    private static function assertSupportedAlgorithms(array $algorithms): void
    {
        $supported = array_map(
            static fn (CoseAlgorithm $algorithm): int => $algorithm->value,
            self::SUPPORTED_ALGORITHMS,
        );

        foreach ($algorithms as $algorithm) {
            if (! in_array($algorithm, $supported, true)) {
                throw InvalidConfiguration::unsupportedAlgorithm($algorithm);
            }
        }
    }

    private static function hostFromUrl(?string $url): ?string
    {
        if ($url === null || $url === '') {
            return null;
        }

        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : null;
    }
}
