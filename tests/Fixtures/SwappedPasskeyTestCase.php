<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Fixtures;

use RoundlyConsulting\Passkeys\Tests\Support\CustomPasskey;
use RoundlyConsulting\Passkeys\Tests\TestCase;

/**
 * The suite's base case with `passkeys.model` already pointed at {@see CustomPasskey}
 * BEFORE the providers boot.
 *
 * This is the distinction the existing `tests/Feature/ConfiguredModelTest.php` cannot draw:
 * it swaps in a `beforeEach()`, i.e. *after* the providers have booted. That reads back
 * correctly and is a perfectly good test of the resolver, but a real host sets
 * `passkeys.model` in `config/passkeys.php` — before boot — and anything the provider hung
 * on the packaged class at boot would stay there. A swap applied in the test body is
 * structurally incapable of seeing that (the reviews bug), which is why this directory
 * exists rather than one more case in that file.
 *
 * Note the `array_merge(parent::configBeforeBoot(), …)`: dropping it would silently discard
 * the base case's rp/origins wiring and every ceremony here would fail for the wrong reason.
 *
 * @see TestCase
 */
abstract class SwappedPasskeyTestCase extends TestCase
{
    /**
     * @return array<string, mixed>
     */
    protected function configBeforeBoot(): array
    {
        return array_merge(parent::configBeforeBoot(), [
            'passkeys.model' => CustomPasskey::class,
        ]);
    }
}
