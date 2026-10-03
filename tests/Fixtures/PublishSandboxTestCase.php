<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Tests\Fixtures;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\File;
use RoundlyConsulting\Passkeys\Tests\TestCase;

/**
 * The suite's base case with `database/` pointed at a throwaway directory per test, set
 * before the providers boot — the migration publish destinations are fixed then.
 *
 * Publishing into the shared testbench skeleton raced the parallel suite: every process
 * migrates whatever sits in the skeleton's `database/migrations`, so another process
 * booting while the published passkeys migrations were there ran them on top of the
 * package's own — or half-read one being deleted — and failed whichever test was booting.
 *
 * @see TestCase
 */
abstract class PublishSandboxTestCase extends TestCase
{
    private string $sandbox = '';

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $this->sandbox = sys_get_temp_dir().'/passkeys-publish-'.bin2hex(random_bytes(6));
        File::ensureDirectoryExists($this->sandbox.'/database/migrations');

        $app->useDatabasePath($this->sandbox.'/database');
    }

    protected function tearDown(): void
    {
        if ($this->sandbox !== '') {
            File::deleteDirectory($this->sandbox);
        }

        parent::tearDown();
    }
}
