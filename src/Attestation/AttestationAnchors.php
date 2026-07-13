<?php

declare(strict_types=1);

namespace RoundlyConsulting\Passkeys\Attestation;

use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Crypto\X509\Chain;
use RoundlyConsulting\Passkeys\DataTransferObjects\PasskeyConfig;
use RoundlyConsulting\Passkeys\Exceptions\InvalidConfiguration;

/**
 * The relying party's attestation trust anchors — which roots an attestation
 * chain may terminate at, per format.
 *
 * This is a TRUST store, which is why it lives here and not in crypto: crypto
 * answers "is this certificate signed by that one", never "do I trust it".
 *
 * Anchors come from two sources, both host-controlled:
 *  - the roots shipped in `resources/roots/<format>/*.pem` (Google's published
 *    hardware-attestation roots), unless `attestation_anchors.defaults` is false;
 *  - `attestation_anchors.paths.<format>` — absolute PEM or PEM-bundle paths.
 *
 * A later metadata source (FIDO MDS) would be a third source behind the same two
 * methods, with no interface change.
 */
final class AttestationAnchors
{
    /**
     * PEM blocks, extracted verbatim. A bundle is a list of independent anchors,
     * never a chain, so each block is parsed on its own.
     */
    private const string PEM_BLOCK = '/-----BEGIN CERTIFICATE-----[A-Za-z0-9+\/=\s]+?-----END CERTIFICATE-----/';

    /** @var array<string, list<Certificate>> */
    private array $loaded = [];

    private readonly string $shippedRoots;

    public function __construct(
        private readonly PasskeyConfig $config,
        ?string $shippedRoots = null,
    ) {
        $this->shippedRoots = $shippedRoots ?? __DIR__.'/../../resources/roots';
    }

    /**
     * Every anchor configured for a format, shipped defaults first. Memoized for
     * the request; the files are local, so no cache layer is involved.
     *
     * @return list<Certificate>
     *
     * @throws InvalidConfiguration
     */
    public function for(string $format): array
    {
        if (isset($this->loaded[$format])) {
            return $this->loaded[$format];
        }

        $anchors = [];

        if ($this->config->attestationAnchorDefaults) {
            foreach ($this->shippedPaths($format) as $path) {
                foreach ($this->certificatesIn($format, $path) as $certificate) {
                    $anchors[] = $certificate;
                }
            }
        }

        foreach ($this->config->anchorPathsFor($format) as $path) {
            foreach ($this->certificatesIn($format, $path) as $certificate) {
                $anchors[] = $certificate;
            }
        }

        return $this->loaded[$format] = $anchors;
    }

    /**
     * The anchor that terminates this path, or null when none does.
     *
     * Two shapes are accepted, because authenticators send both:
     *  - the path's last certificate IS an anchor (byte-equal), or
     *  - the path's last certificate is SIGNED BY an anchor, which then completes
     *    the chain (x5c commonly omits the root — Apple always does).
     *
     * @throws InvalidConfiguration
     */
    public function anchorFor(Chain $path, string $format): ?Certificate
    {
        $anchors = $this->for($format);
        $top = $path->root();

        foreach ($anchors as $anchor) {
            if ($anchor->equals($top)) {
                return $anchor;
            }
        }

        foreach ($anchors as $anchor) {
            if ($top->isSignedBy($anchor)) {
                return $anchor;
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function shippedPaths(string $format): array
    {
        // The format comes off the wire, so it never reaches the filesystem as
        // anything but a whitelisted directory name.
        if (preg_match('/^[a-z0-9-]{1,32}$/', $format) !== 1) {
            return [];
        }

        $found = glob($this->shippedRoots.'/'.$format.'/*.pem');

        return $found === false ? [] : $found;
    }

    /**
     * @return list<Certificate>
     *
     * @throws InvalidConfiguration
     */
    private function certificatesIn(string $format, string $path): array
    {
        $contents = is_file($path) && is_readable($path) ? file_get_contents($path) : false;

        // Unreadable or PEM-less is LOUD: a trust store that silently comes back
        // empty turns `basic` into `ignore` without anyone noticing.
        if (! is_string($contents) || preg_match_all(self::PEM_BLOCK, $contents, $matches) < 1) {
            throw InvalidConfiguration::unreadableAttestationAnchor($format, $path);
        }

        $certificates = [];

        foreach ($matches[0] as $pem) {
            try {
                $certificates[] = Certificate::fromPem($pem);
            } catch (CryptoException) {
                throw InvalidConfiguration::unreadableAttestationAnchor($format, $path);
            }
        }

        return $certificates;
    }
}
