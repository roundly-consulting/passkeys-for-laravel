<?php

declare(strict_types=1);

use Illuminate\Support\Arr;
use RoundlyConsulting\Passkeys\Exceptions\CredentialNotFound;

dataset('translation files', ['errors']);

it('ships the same keys in every language', function (string $file): void {
    $en = Arr::dot(require __DIR__.'/../../resources/lang/en/'.$file.'.php');
    $sk = Arr::dot(require __DIR__.'/../../resources/lang/sk/'.$file.'.php');

    expect($en)->not->toBeEmpty()
        ->and(array_keys($sk))->toBe(array_keys($en));
})->with('translation files');

it('keeps every placeholder in every language', function (string $file): void {
    $en = Arr::dot(require __DIR__.'/../../resources/lang/en/'.$file.'.php');
    $sk = Arr::dot(require __DIR__.'/../../resources/lang/sk/'.$file.'.php');

    $placeholders = static function (string $line): array {
        preg_match_all('/:([A-Za-z_]+)/', $line, $matches);
        $names = array_unique($matches[1]);
        sort($names);

        return $names;
    };

    foreach ($en as $key => $line) {
        expect($placeholders((string) ($sk[$key] ?? '')))
            ->toBe($placeholders((string) $line), "Placeholders differ for [{$file}.{$key}].");
    }
})->with('translation files');

it('loads slovak through the package namespace', function (): void {
    app()->setLocale('sk');

    expect(trans('passkeys::errors.credential_not_found'))->toBe('Nenašiel sa žiadny zodpovedajúci prístupový kľúč.')
        ->and(CredentialNotFound::make()->getMessage())->toBe('Nenašiel sa žiadny zodpovedajúci prístupový kľúč.');

    app()->setLocale('en');

    expect(trans('passkeys::errors.credential_not_found'))->toBe('No matching passkey could be found.');
});
