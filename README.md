<!-- roundly-hero:start -->
<p align="center">
  <a href="https://roundly-consulting.com/open-source/docs/passkeys-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=passkeys-for-laravel">
    <img src="https://raw.githubusercontent.com/roundly-consulting/passkeys-for-laravel/main/art/hero.png" alt="Passkeys for Laravel — Roundly open source" width="100%">
  </a>
</p>
<!-- roundly-hero:end -->

<!-- roundly-badges:start -->
<p align="center">
  <a href="https://packagist.org/packages/roundly-consulting/passkeys-for-laravel"><img src="https://img.shields.io/packagist/v/roundly-consulting/passkeys-for-laravel?style=flat-square&label=release" alt="Latest release"></a>
  <a href="https://github.com/roundly-consulting/passkeys-for-laravel/actions/workflows/run-tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/passkeys-for-laravel/run-tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://github.com/roundly-consulting/passkeys-for-laravel/actions/workflows/fix-php-code-style-issues.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/passkeys-for-laravel/fix-php-code-style-issues.yml?branch=main&style=flat-square&label=code%20style" alt="Code style"></a>
  <a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/donate-support%20our%20open%20source-F24E29?style=flat-square&logo=stripe&logoColor=white" alt="Donate"></a>
  <a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/patreon-become%20a%20patron-F96854?style=flat-square&logo=patreon&logoColor=white" alt="Patreon"></a>
  <a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=passkeys-for-laravel#crypto"><img src="https://img.shields.io/badge/crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=flat-square&logo=bitcoin&logoColor=white" alt="Crypto"></a>
</p>
<!-- roundly-badges:end -->

# Passkeys for Laravel

A native WebAuthn / FIDO2 passkey relying party for Laravel: register passkeys and sign users in
with them (ES256, RS256 and EdDSA), with no third-party crypto dependencies. It ships actions, a
model, a challenge store and events, and your application wires its own endpoints on top.

## Installation

Requires PHP 8.4 (`ext-json`; `ext-sodium` for EdDSA keys) and Laravel 12 or 13.

```bash
composer require roundly-consulting/passkeys-for-laravel
php artisan vendor:publish --tag="passkeys-migrations"
php artisan migrate
```

Set `PASSKEYS_ORIGINS` (e.g. `https://example.com`): no ceremony runs until at least one origin is
allowed. If your users have UUID/ULID keys, set `PASSKEYS_KEY_TYPE` **before** migrating.

## Usage

Give your user model the contract and an opaque user-handle column:

```php
use RoundlyConsulting\Passkeys\Concerns\InteractsWithPasskeys;
use RoundlyConsulting\Passkeys\Contracts\HasPasskeys;

final class User extends Authenticatable implements HasPasskeys
{
    use InteractsWithPasskeys;
}

// in a migration
Schema::table('users', fn (Blueprint $table) => $table->passkeyUserHandle());
```

Register a passkey: return the options, then verify what the browser posts back:

```php
use RoundlyConsulting\Passkeys\DataTransferObjects\RegistrationResponseData;
use RoundlyConsulting\Passkeys\Facades\Passkeys;

return response()->json(Passkeys::for($user)->registrationOptions());

$passkey = Passkeys::for($user)->register(
    RegistrationResponseData::fromArray($request->all()),
    name: 'MacBook Touch ID',
);
```

In the browser, pass `options.publicKey` through `PublicKeyCredential.parseCreationOptionsFromJSON()`
into `navigator.credentials.create()`, then POST the credential with the `ceremonyId`:

```js
const options = await (await fetch('/passkeys/options')).json();
const credential = await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey),
});
await fetch('/passkeys', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...credential.toJSON(), ceremonyId: options.ceremonyId }) });
```

Sign in without a username: the same with `parseRequestOptionsFromJSON()` and
`navigator.credentials.get()`, then verify:

```php
use RoundlyConsulting\Passkeys\DataTransferObjects\AuthenticationResponseData;

return response()->json(Passkeys::authenticationOptions());

$passkey = Passkeys::authenticate(AuthenticationResponseData::fromArray($request->all()));

Auth::login($passkey->authenticatable);
```

<!-- roundly-docs:start -->
## Documentation

The full documentation — configuration, every feature and its API, and testing — lives on our
website: **[roundly-consulting.com/open-source/docs/passkeys-for-laravel](https://roundly-consulting.com/open-source/docs/passkeys-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=passkeys-for-laravel)**

Release notes are in [CHANGELOG.md](CHANGELOG.md). To contribute, see the
[contributing guide](https://github.com/roundly-consulting/.github/blob/main/CONTRIBUTING.md).
<!-- roundly-docs:end -->

<!-- roundly-support:start -->
## Support our work

This package is free and open source, built and maintained by
[Roundly Consulting](https://roundly-consulting.com/open-source?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=passkeys-for-laravel).
If it saves you time, please consider supporting our open-source work — a one-time donation, a
monthly pledge on Patreon or a crypto donation helps fund maintenance, new features and new
packages.

<a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/Donate-Support%20Roundly%20open%20source-F24E29?style=for-the-badge&logo=stripe&logoColor=white" alt="Donate to Roundly open source"></a>
<a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/Patreon-Become%20a%20patron-F96854?style=for-the-badge&logo=patreon&logoColor=white" alt="Become a patron on Patreon"></a>
<a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=passkeys-for-laravel#crypto"><img src="https://img.shields.io/badge/Crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate crypto: BTC, ETH, BNB or SOL"></a>
<!-- roundly-support:end -->

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md). Copyright © Roundly Consulting.
