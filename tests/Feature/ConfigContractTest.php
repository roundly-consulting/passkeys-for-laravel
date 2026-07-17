<?php

declare(strict_types=1);

/**
 * The config contract, pinned in both directions:
 *
 *  - forward — every key the code reads is shipped. This is shops #18, whose entire
 *    store-credit feature read `shops.payments.*` while the file shipped `payment.*`; 330
 *    tests stayed green because the suite set the same wrong key.
 *  - reverse — every shipped leaf is read. A documented key nothing reads is dead config
 *    that lies to the host — and here that is a security claim, not a convenience: a host
 *    that sets `attestation_trust`, `aaguids.allowed` or `reject_unknown_fmt` believes it has
 *    tightened who may enrol. A key nothing consults would leave the door open and say
 *    nothing. media #27's size cap that never applied is the same bug with lower stakes.
 */
it('ships exactly the config keys it reads', function (): void {
    expect(__DIR__.'/../../config/passkeys.php')->toSatisfyConfigContract([__DIR__.'/../../src', __DIR__.'/../../database'], [
        // `passkeys.model` is read through the toolkit's ModelResolver seam
        // (`PasskeyModel::class()`) rather than a literal `config()` call, and
        // `passkeys.key_type` through `KeyType::fromConfig(…)` in the migration (database/ is
        // scanned above). Both are real reads — one drives the model swap, the other the
        // authenticatable morph column type — but neither is a `config(` token, so the prefix
        // is what makes them visible to the scraper.
        'extraReadPrefixes' => ['passkeys.'],

        // Deliberately NO `excludeFromReverse` for the provider. PasskeysServiceProvider is
        // this package's single biggest reader: register() builds PasskeyConfig from config
        // and aboutData() reads a dozen leaves for real. Excluding it would discard readers
        // and gut the reverse direction.
    ]);
});
