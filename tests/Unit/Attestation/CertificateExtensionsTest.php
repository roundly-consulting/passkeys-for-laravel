<?php

declare(strict_types=1);

use RoundlyConsulting\Crypto\X509\Certificate;
use RoundlyConsulting\Passkeys\Attestation\Support\CertificateExtensions;
use RoundlyConsulting\Passkeys\Tests\Support\Pki;
use RoundlyConsulting\Passkeys\Tests\Support\RawCertificate;

function certificateWith(string $extensions): Certificate
{
    return Certificate::fromDer(RawCertificate::mint($extensions)->der);
}

it('lets a CA with keyCertSign issue certificates', function (string $extensions): void {
    expect((new CertificateExtensions)->mayIssueCertificates(certificateWith($extensions)))->toBeTrue();
})->with([
    'CA:TRUE + keyCertSign' => [Pki::CA],
    'CA:TRUE without keyUsage' => [Pki::CA_WITHOUT_KEY_USAGE],
    'CA:TRUE with a pathLenConstraint' => [Pki::CA_PATH_LENGTH_ZERO],
    'CA:TRUE with a pathLenConstraint wider than 64 bits' => ['2.5.29.19 = DER:300E0101FF0209010000000000000000'],
]);

it('refuses to let anything else issue, failing closed on what it cannot read', function (string $extensions): void {
    expect((new CertificateExtensions)->mayIssueCertificates(certificateWith($extensions)))->toBeFalse();
})->with([
    'no extensions (v1)' => [''],
    'end entity' => [Pki::END_ENTITY],
    'CA:TRUE without keyCertSign' => [Pki::CA_WITHOUT_CERT_SIGN],
    'keyCertSign without basicConstraints' => [Pki::CERT_SIGN_WITHOUT_BASIC_CONSTRAINTS],
    'basicConstraints that is not DER' => ['2.5.29.19 = DER:0000'],
    'keyUsage that is not a BIT STRING' => ["basicConstraints = critical,CA:TRUE\n2.5.29.15 = DER:0400"],
    'keyUsage claiming 8 unused bits' => ["basicConstraints = critical,CA:TRUE\n2.5.29.15 = DER:03020804"],
    'keyUsage with no bits at all' => ["basicConstraints = critical,CA:TRUE\n2.5.29.15 = DER:030100"],
    'negative pathLenConstraint' => ['2.5.29.19 = DER:30060101FF0201FF'],
    'negative pathLenConstraint wider than 64 bits' => ['2.5.29.19 = DER:300E0101FF0209FF0000000000000000'],
]);

it('reads the pathLenConstraint, null when there is none', function (string $extensions, ?int $expected): void {
    expect((new CertificateExtensions)->pathLengthConstraint(certificateWith($extensions)))->toBe($expected);
})->with([
    'no basicConstraints' => ['keyUsage = critical,keyCertSign', null],
    'CA:TRUE without a limit' => [Pki::CA_WITHOUT_KEY_USAGE, null],
    'pathlen:0' => [Pki::CA_PATH_LENGTH_ZERO, 0],
    'pathlen:2' => ['basicConstraints = critical,CA:TRUE,pathlen:2', 2],
    'wider than 64 bits' => ['2.5.29.19 = DER:300E0101FF0209010000000000000000', null],
    'unreadable reads as zero' => ['2.5.29.19 = DER:0000', 0],
    'negative reads as zero' => ['2.5.29.19 = DER:30060101FF0201FF', 0],
]);

it('still treats an unreadable basicConstraints as a CA when judging a leaf', function (): void {
    expect((new CertificateExtensions)->isCertificateAuthority(certificateWith('2.5.29.19 = DER:0000')))->toBeTrue()
        ->and((new CertificateExtensions)->isCertificateAuthority(certificateWith(Pki::END_ENTITY)))->toBeFalse();
});
