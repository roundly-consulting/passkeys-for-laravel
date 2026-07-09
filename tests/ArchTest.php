<?php

declare(strict_types=1);

// Independence guard: the production relying party must implement WebAuthn/FIDO2
// natively and never reach for a third-party crypto, CBOR, or WebAuthn library.
// The only external vendor namespace allowed anywhere in src/ is our own
// RoundlyConsulting\Enums helper package (the one sanctioned dependency).

arch('src does not use forbidden third-party vendor namespaces')
    ->expect('RoundlyConsulting\Passkeys')
    ->not->toUse([
        'Acme',
        'Webauthn',
        'Cose',
        'CBOR',
        'Spomky',
        'Base64Url\\',
        'ParagonIE',
        'phpseclib',
        'phpseclib3',
        'Firebase\\JWT',
        'lbuchs',
        'web-auth',
    ]);

arch('src declares strict types')
    ->expect('RoundlyConsulting\Passkeys')
    ->toUseStrictTypes();

arch('actions are final')
    ->expect('RoundlyConsulting\Passkeys\Actions')
    ->toBeClasses()
    ->toBeFinal();

arch('data transfer objects are final and readonly')
    ->expect('RoundlyConsulting\Passkeys\DataTransferObjects')
    ->toBeFinal()
    ->toBeReadonly();

arch('enums are backed enums')
    ->expect('RoundlyConsulting\Passkeys\Enums')
    ->toBeEnums();

arch('exceptions extend the package base exception')
    ->expect('RoundlyConsulting\Passkeys\Exceptions')
    ->toExtend('RoundlyConsulting\Passkeys\Exceptions\PasskeyException')
    ->ignoring('RoundlyConsulting\Passkeys\Exceptions\PasskeyException');

arch('no debugging leftovers')
    ->expect(['dd', 'dump', 'ray', 'var_dump', 'print_r'])
    ->not->toBeUsed();
