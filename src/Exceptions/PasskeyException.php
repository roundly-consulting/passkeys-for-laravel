<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Exceptions;

use Illuminate\Support\Facades\Lang;
use RuntimeException;

/**
 * Base type for every passkey ceremony failure. Hosts may catch this broadly,
 * or catch any of the typed children for finer control.
 *
 * Messages are resolved through the package translation namespace so hosts can
 * localise them (`resources/lang/vendor/passkeys/<locale>/errors.php`).
 */
abstract class PasskeyException extends RuntimeException
{
    /** A lower layer's own, untranslated account of the failure — logged, never shown. */
    private string $reason = '';

    /**
     * Merged into the log entry by Laravel's exception handler, so the lower
     * layer's reason stays available to developers without reaching the
     * localised message.
     *
     * @return array<string, string>
     */
    public function context(): array
    {
        return $this->reason === '' ? [] : ['reason' => $this->reason];
    }

    protected function withReason(string $reason): static
    {
        $this->reason = $reason;

        return $this;
    }

    /**
     * @param  array<string, string>  $replace
     */
    protected static function trans(string $key, array $replace = []): string
    {
        $line = __('passkeys::errors.'.$key, $replace);

        return is_string($line) ? $line : $key;
    }

    /**
     * A message fragment the package owns (`errors.<group>.<code>`), in the app
     * locale. Anything that is not one of those codes — a host's own verifier
     * passing its own wording — is kept verbatim.
     *
     * @param  array<string, string>  $replace
     */
    protected static function fragment(string $group, string $code, array $replace = []): string
    {
        $key = $group.'.'.$code;

        if (preg_match('/^[a-z][a-z0-9_]*$/', $code) !== 1 || ! Lang::has('passkeys::errors.'.$key)) {
            return $code;
        }

        return self::trans($key, $replace);
    }
}
