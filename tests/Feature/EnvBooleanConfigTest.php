<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\Exceptions\InvalidConfiguration;

/**
 * Regression (env-boolean sweep): the three switches were read with `(bool) env(...)` in the
 * config file, `(bool)` in PasskeyConfig and `=== true` / `is_bool()` in `about`. env() only
 * converts "true"/"false", so `PASSKEYS_ALLOW_CROSS_ORIGIN=off` was cast to true (iframe
 * ceremonies accepted), and a host-set "1" rendered OFF in `about` while the ceremony ran
 * with it on. The DTO and the `about` rows now read each switch as a boolean the same way.
 */
function passkeysAboutRow(string $row): string
{
    Artisan::call('about', ['--only' => 'passkeys', '--json' => true]);

    /** @var array{passkeys: array<string, string>} $about */
    $about = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

    return $about['passkeys'][$row];
}

dataset('passkeys env switches', [
    '"1"' => ['1', true],
    '"on"' => ['on', true],
    '"yes"' => ['yes', true],
    '"true"' => ['true', true],
    '"0"' => ['0', false],
    '"off"' => ['off', false],
    '"no"' => ['no', false],
    '"false"' => ['false', false],
]);

it('reads allow_cross_origin from an env string', function (string $value, bool $on): void {
    config()->set('passkeys.allow_cross_origin', $value);

    expect(PasskeyConfig::fromArray(['allow_cross_origin' => $value])->allowCrossOrigin)->toBe($on)
        ->and(passkeysAboutRow('origins'))->toEndWith('cross-origin '.($on ? 'ON' : 'OFF'));
})->with('passkeys env switches');

it('reads reject_unknown_fmt from an env string', function (string $value, bool $on): void {
    config()->set('passkeys.reject_unknown_fmt', $value);

    expect(PasskeyConfig::fromArray(['reject_unknown_fmt' => $value])->rejectUnknownFmt)->toBe($on)
        ->and(passkeysAboutRow('attestation'))->toEndWith('unknown formats '.($on ? 'REJECTED' : 'ACCEPTED'));
})->with('passkeys env switches');

it('reads attestation_anchors.defaults from an env string', function (string $value, bool $on): void {
    config()->set('passkeys.attestation_anchors.defaults', $value);

    expect(PasskeyConfig::fromArray(['attestation_anchors' => ['defaults' => $value]])->attestationAnchorDefaults)->toBe($on)
        ->and(passkeysAboutRow('trust_anchors'))->toStartWith('bundled roots '.($on ? 'ON' : 'OFF'));
})->with('passkeys env switches');

it('refuses an unrecognised switch value instead of reading the default', function (array $config, string $key): void {
    // `PASSKEYS_ALLOW_CROSS_ORIGIN=maybe` must stop the app, not quietly pick a default.
    expect(fn (): PasskeyConfig => PasskeyConfig::fromArray($config))->toThrow(
        InvalidConfiguration::class,
        "Configuration value [{$key}] must be a boolean (true/false, 1/0, on/off or yes/no), [maybe] given.",
    );
})->with([
    'allow_cross_origin' => [['allow_cross_origin' => 'maybe'], 'passkeys.allow_cross_origin'],
    'reject_unknown_fmt' => [['reject_unknown_fmt' => 'maybe'], 'passkeys.reject_unknown_fmt'],
    'attestation_anchors.defaults' => [['attestation_anchors' => ['defaults' => 'maybe']], 'passkeys.attestation_anchors.defaults'],
]);

/**
 * End to end through the shipped config file: a `(bool) env(...)` cast there turns "off"
 * into true before any code can read it.
 */
it('honours env-string switches through the shipped config file', function (string $value, bool $on): void {
    $keys = [
        'PASSKEYS_ALLOW_CROSS_ORIGIN',
        'PASSKEYS_REJECT_UNKNOWN_FMT',
        'PASSKEYS_ATTESTATION_DEFAULT_ANCHORS',
    ];

    foreach ($keys as $key) {
        $_SERVER[$key] = $value;
    }

    try {
        $shipped = require __DIR__.'/../../config/passkeys.php';
    } finally {
        foreach ($keys as $key) {
            unset($_SERVER[$key]);
        }
    }

    config()->set('passkeys', $shipped);
    $config = PasskeyConfig::fromArray($shipped);

    expect($config->allowCrossOrigin)->toBe($on)
        ->and($config->rejectUnknownFmt)->toBe($on)
        ->and($config->attestationAnchorDefaults)->toBe($on)
        ->and(passkeysAboutRow('origins'))->toEndWith('cross-origin '.($on ? 'ON' : 'OFF'))
        ->and(passkeysAboutRow('attestation'))->toEndWith('unknown formats '.($on ? 'REJECTED' : 'ACCEPTED'))
        ->and(passkeysAboutRow('trust_anchors'))->toStartWith('bundled roots '.($on ? 'ON' : 'OFF'));
})->with('passkeys env switches');

it('reads a blank switch as not set, so its default applies in the DTO and about (strict config)', function (): void {
    config()->set('passkeys.allow_cross_origin', '');
    config()->set('passkeys.reject_unknown_fmt', ' ');
    config()->set('passkeys.attestation_anchors.defaults', '');
    config()->set('passkeys.challenge.store', '');

    $config = PasskeyConfig::fromArray(['allow_cross_origin' => '', 'reject_unknown_fmt' => ' ', 'attestation_anchors' => ['defaults' => '']]);

    expect($config->allowCrossOrigin)->toBeFalse()
        ->and($config->rejectUnknownFmt)->toBeFalse()
        ->and($config->attestationAnchorDefaults)->toBeTrue()
        ->and(passkeysAboutRow('origins'))->toEndWith('cross-origin OFF')
        ->and(passkeysAboutRow('attestation'))->toEndWith('unknown formats ACCEPTED')
        ->and(passkeysAboutRow('trust_anchors'))->toStartWith('bundled roots ON')
        ->and(passkeysAboutRow('challenge'))->toEndWith('store DEFAULT');
});
