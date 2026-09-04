# Rekor client for PHP

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/rekor-client/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/rekor-client/actions/workflows/ci.yml)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/rekor-client?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/rekor-client)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-level%209-2a5ea7?logo=php&logoColor=white)](https://phpstan.org)
[![License](https://img.shields.io/packagist/l/k2gl/rekor-client?color=yellowgreen)](https://packagist.org/packages/k2gl/rekor-client)

Submit entries to a Rekor transparency log from PHP — both the original
[v1](https://github.com/sigstore/rekor) REST log and
[v2](https://github.com/sigstore/rekor-tiles) (rekor-tiles) — and get back the
transparency-log entry Rekor integrated, the same value
[`k2gl/sigstore-bundle`](https://github.com/k2gl/sigstore-bundle) takes, so a signer goes
**submit → add to bundle** with no glue in between.

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
use K2gl\RekorClient\RekorApiVersion;
use K2gl\RekorClient\RekorClient;
use K2gl\RekorClient\Verifier;
use K2gl\RekorClient\KeyDetails;

$rekor = new RekorClient(
    httpClient:     $psr18Client,
    requestFactory: $psr17Factory,
    streamFactory:  $psr17Factory,
    baseUrl:        'https://rekor.sigstore.dev',
    apiVersion:     RekorApiVersion::V1,
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

### Which log version

Take both the URL and the version from the log entry in Sigstore's **signing config**
rather than assuming — that is what `majorApiVersion` there is for, and
`RekorApiVersion::from()` accepts it directly. It matters: Sigstore's default signing
config still lists only `rekor.sigstore.dev` at major version **1**, and the v2 logs live
in a separate, opt-in config.

The two differ in more than the path. v1 takes the verifier as PEM and the digest as hex,
answers with a map keyed by entry UUID, hex-encodes proof hashes, and stamps every entry
with an integrated time and a signed entry timestamp. v2 takes raw DER and base64, answers
with the entry itself, and has no per-entry time — a v2 bundle needs an RFC 3161
timestamp to be verifiable. All of that is handled here; the only choice you make is the
version.

A v1 submission takes a SHA-256, SHA-384 or SHA-512 digest (hashedrekord `0.0.1` names the
algorithm, and it is read from the digest length).

### DSSE attestations

Neither version has a DSSE entry type. Submit the DSSE **PAE** digest and the envelope
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

This package covers **submission** (the write path a signer needs) against both log
versions. Reading back entries and tiles (the C2SP tlog-tiles read API) is not implemented yet;
verifying an entry already in a bundle is what
[`k2gl/sigstore-verify`](https://github.com/k2gl/sigstore-verify) does.

## Pull requests are always welcome
[Collaborate with pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request)
