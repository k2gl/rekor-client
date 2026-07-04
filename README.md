# Rekor v2 client for PHP

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/rekor-client/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/rekor-client/actions/workflows/ci.yml)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/rekor-client?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/rekor-client)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-level%209-2a5ea7?logo=php&logoColor=white)](https://phpstan.org)
[![License](https://img.shields.io/packagist/l/k2gl/rekor-client?color=yellowgreen)](https://packagist.org/packages/k2gl/rekor-client)

Submit entries to a [Rekor v2](https://github.com/sigstore/rekor-tiles) (rekor-tiles)
transparency log from PHP and get back the transparency-log entry Rekor integrated —
the same value [`k2gl/sigstore-bundle`](https://github.com/k2gl/sigstore-bundle) takes,
so a signer goes **submit → add to bundle** with no glue in between.

Transport is any [PSR-18](https://www.php-fig.org/psr/psr-18/) HTTP client you supply
(Guzzle, Symfony HttpClient, …). This package speaks the Rekor API; it owns no socket.

## Requirements

- PHP 8.1+
- A PSR-18 HTTP client and a PSR-17 factory (e.g. `nyholm/psr7` + `symfony/http-client`)
- [`k2gl/sigstore-bundle`](https://github.com/k2gl/sigstore-bundle)

## Installation

```bash
composer require k2gl/rekor-client
```

## Usage

```php
use K2gl\RekorClient\RekorClient;
use K2gl\RekorClient\Verifier;
use K2gl\RekorClient\KeyDetails;

$rekor = new RekorClient(
    httpClient:     $psr18Client,
    requestFactory: $psr17Factory,
    streamFactory:  $psr17Factory,
    baseUrl:        'https://rekor.sigstore.dev', // the v2 log URL from your signing config
);

// A hashedrekord entry: the artifact digest, the signature, and the key or
// certificate that signed it.
$entry = $rekor->submitHashedRekord(
    digest:    $artifactSha256,        // raw 32-byte digest
    signature: $rawSignature,
    verifier:  Verifier::certificate($fulcioLeafDer, KeyDetails::PKIX_ECDSA_P256_SHA_256),
);

// $entry is a K2gl\SigstoreBundle\TransparencyLogEntry — drop it straight in:
$json = BundleBuilder::forMessageSignature($messageSignature)
    ->withCertificate($fulcioLeafDer)
    ->addTransparencyLogEntry($entry)
    ->toJson();
```

### DSSE attestations

Rekor v2 has no DSSE entry type. Submit the DSSE **PAE** digest and the envelope
signature as a hashedrekord — the entry Rekor returns is the one a DSSE bundle carries.

### Signing identity

- `Verifier::publicKey($der, $keyDetails)` — a bare public key.
- `Verifier::certificate($der, $keyDetails)` — a Fulcio (keyless) certificate.

`KeyDetails` names the algorithm (`PKIX_ECDSA_P256_SHA_256`, `PKIX_ED25519`, …).

## Errors

Everything thrown implements `K2gl\RekorClient\Exception\RekorClientException`:
`RekorRequestException` (transport failed / request could not be built),
`RekorResponseException` (Rekor answered with an error status or an unparseable body,
with the HTTP `statusCode`), and `InvalidArgumentException` (bad input).

## Scope

This release covers **submission** (the write path a signer needs) against Rekor v2.
Reading back entries and tiles (the C2SP tlog-tiles read API) is not implemented yet;
verifying an entry already in a bundle is what
[`k2gl/sigstore-verify`](https://github.com/k2gl/sigstore-verify) does.

## Pull requests are always welcome
[Collaborate with pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request)
