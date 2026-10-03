<?php

declare(strict_types=1);

use RoundlyConsulting\Passkeys\Tests\Fixtures\PublishSandboxTestCase;
use RoundlyConsulting\Passkeys\Tests\Fixtures\SwappedPasskeyTestCase;
use RoundlyConsulting\Passkeys\Tests\TestCase;

/**
 * ArchTest.php is now bound explicitly (`->in()` accepts a file path as well as a directory):
 * `swappableModelsAreNotFinal` reads the `passkeys.model` config default, so it needs the app
 * booted, and an arch file is not automatically test-cased. It previously ran with no test
 * case at all.
 */
uses(TestCase::class)->in(__DIR__.'/ArchTest.php', 'Feature', 'Unit');

/**
 * The model-swap proof needs `passkeys.model` pointed at the host subclass BEFORE the
 * providers boot, so it runs on its own base case in its own directory — Pest binds a test
 * case per directory, not per file.
 */
uses(SwappedPasskeyTestCase::class)->in(__DIR__.'/ModelSwap');

/**
 * Publishing writes files: into a throwaway database/ set before boot, never the testbench
 * skeleton whose `database/migrations` every parallel process migrates.
 */
uses(PublishSandboxTestCase::class)->in(__DIR__.'/Publish');
