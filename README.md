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
**submit → add to bundle** with no glue in between. And read a v2 log back: its signed
checkpoint, and any entry with an inclusion proof computed from the log's hash tiles.

Transport is any [PSR-18](https://www.php-fig.org/psr/psr-18/) HTTP client you supply
(Guzzle, Symfony HttpClient, …). This package speaks the Rekor API; it owns no socket.

## Requirements

- PHP 8.1+
- A PSR-18 HTTP client and a PSR-17 factory (e.g. `nyholm/psr7` + `symfony/http-client`)
- [`k2gl/sigstore-bundle`](https://github.com/k2gl/sigstore-bundle) and
  [`k2gl/signed-note`](https://github.com/k2gl/signed-note) (checkpoints)

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

This client submits hashedrekord entries. For a DSSE attestation, submit the **PAE** digest
and the envelope signature — the entry Rekor returns is the one a DSSE bundle carries.

### Signing identity

- `Verifier::publicKey($der, $keyDetails)` — a bare public key.
- `Verifier::certificate($der, $keyDetails)` — a Fulcio (keyless) certificate.

`KeyDetails` names the algorithm (`PKIX_ECDSA_P256_SHA_256`, `PKIX_ED25519`, …).

### Retries and duplicates

A submission is tried again when the log answers with something that means "busy, come
back" — a transport failure, or `408`, `429`, `499`, `500`, `502`, `503`, `504` — backing
off exponentially with jitter, and waiting exactly as long as a `Retry-After` header asks.
Two extra attempts by default; pass `retries: 0` to send once, or a `sleeper` closure to
control the waiting (tests do).

A duplicate is not retried, because the entry is already in the log. What that means
differs by version, and both are handled: **v1** answers `409` with a `Location` for the
entry that is already there, so the client follows it and returns that entry — which is
exactly the case a retry runs into when the first attempt reached the log but its answer
did not come back. **v2** answers `409` with the entry's index in `x-log-index` and has no
write-side endpoint to read it from, so the client reports the index; `LogReader::entry()`
below fetches it from the read path.

## Reading the log

A Rekor v2 log is served as [tlog-tiles](https://c2sp.org/tlog-tiles): a signed checkpoint
(the log's head), hash tiles 256 wide at every level of the Merkle tree, and entry bundles
holding the entries themselves. `LogReader` puts those together into the same
`TransparencyLogEntry` a submission returns — with an inclusion proof against the current
checkpoint — so an entry can go into a bundle whether you submitted it or found it.

```php
use K2gl\RekorClient\LogReader;

$reader = new LogReader(
    httpClient:     $psr18Client,
    requestFactory: $psr17Factory,
    baseUrl:        'https://log2025-1.rekor.sigstore.dev',
    origin:         'log2025-1.rekor.sigstore.dev',   // the checkpoint's first line
    publicKeyDer:   $logPublicKeyDer,                 // tlogs[].publicKey.rawBytes in the trusted root
);

$checkpoint = $reader->checkpoint();      // K2gl\SignedNote\Checkpoint: origin, treeSize, rootHash
$entry      = $reader->entry(114108965);  // TransparencyLogEntry with an inclusion proof
$entries    = $reader->entries(from: 114108900, count: 100); // the same, in bulk
```

The reader takes the log's name and key — both from Sigstore's trusted root — and every read
starts from a checkpoint verified with that key. A proof is computed from the tiles the
entry's path runs through (a handful of requests, whatever the log's size) and checked to
reproduce the checkpoint's root before the entry is handed out; a tile that does not fit
the tree, a bundle with the wrong number of entries or a checkpoint of another log are
errors, never a best effort. Entries are stamped with the log id the trusted root lists:
for an Ed25519 log the note key hash over origin and key, otherwise SHA-256 of the DER key.

A log keeps growing while you read it, so the partial tile at its head can be replaced by
a wider one between the checkpoint and the tiles. The reader notices (the tile is gone),
takes a fresh checkpoint and goes once more; `entries()` proves every entry of a call
against one and the same checkpoint. Reading past the head is not an error for
`entries()` (it returns what is there), while `entry()` insists on its index.

The test suite reads a recorded slice of the public log — checkpoint, head bundle and the
tiles of one proof, taken by `tests/fixtures/rekor-v2/record.php` — with the log key from the
trusted root, and an in-memory log of 70 000 entries laid out the way a real one is.

A **v1** log answers for its entries itself: `RekorClient::entry($logIndex)` on a v1 client
is `GET /api/v1/log/entries?logIndex=…`, and the entry comes back the way a submission does,
inclusion promise and proof included. There is nothing to compute, and nothing verified here
— that stays with `k2gl/sigstore-verify`.

## Errors

Everything thrown implements `K2gl\RekorClient\Exception\RekorClientException`:
`RekorRequestException` (transport failed / request could not be built),
`RekorResponseException` (Rekor answered with an error status or an unparseable body,
with the HTTP `statusCode`), and `InvalidArgumentException` (bad input).

## Scope

This package covers **submission** (the write path a signer needs) against both log
versions, and **reading** entries back — a v2 log through the tlog-tiles API, a v1 log
through its REST API. Verifying an entry already in a bundle — identity, signature,
timestamps — is what [`k2gl/sigstore-verify`](https://github.com/k2gl/sigstore-verify) does.

## Pull requests are always welcome
[Collaborate with pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request)
