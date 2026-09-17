# Changelog

## 1.4.0

- `RekorClient::entry($logIndex)` reads an entry back from a **v1** log
  (`GET /api/v1/log/entries?logIndex=…`), parsed exactly as a submission response is —
  inclusion promise and proof included. On a v2 client it points at `LogReader`, since v2
  has no such endpoint. A recorded response from rekor.sigstore.dev is the fixture.

## 1.3.0

- **`LogReader` reads a Rekor v2 log** through its tlog-tiles API: `checkpoint()` returns the
  log's head verified with the log's key (a `K2gl\SignedNote\Checkpoint`), and `entry()` /
  `entries()` return `TransparencyLogEntry` values with inclusion proofs computed from the
  hash tiles and checked against that checkpoint — the same value a submission returns, so
  a duplicate `409` from v2 is no longer a dead end. Fail-closed: a checkpoint of another
  log or under another key, a tile of the wrong size, a bundle with the wrong number of
  entries, or tiles that do not reproduce the root are all errors. When the head tile moves
  on between the checkpoint and the tiles, the reader takes a fresh checkpoint once.
- Log ids follow the trusted root: the note key hash over origin and key for an Ed25519
  log, SHA-256 of the DER key otherwise.
- The test suite carries a recorded slice of `log2025-1.rekor.sigstore.dev` and checks the
  Merkle arithmetic against the Certificate Transparency test tree.
- Requires `k2gl/signed-note` ^1.1 for the checkpoint.

## 1.2.0

- **Submissions are retried** when the log answers with a transport failure or one of the
  statuses that mean "busy, come back" (`408`, `429`, `499`, `500`, `502`, `503`, `504`),
  backing off exponentially with jitter and honouring `Retry-After`. Two extra attempts by
  default, `retries: 0` to send once. This is not hypothetical: a single `499` from the log
  ("add entry: await: context canceled") is enough to fail a signing run.
- **A duplicate entry is no longer just an error.** Rekor v1 answers `409` with a
  `Location` for the entry that is already logged, and the client now follows it and
  returns that entry — the case a retry meets when the first attempt reached the log but
  its answer did not come back. Rekor v2 has no write-side endpoint to read it from, so
  its `409` is reported with the log index from `x-log-index`.

## 1.1.0

- **Rekor v1 submission.** `RekorClient` now speaks both major versions of the log API,
  chosen with the new `RekorApiVersion` enum whose case values are the `majorApiVersion`
  Sigstore publishes per log in the signing config. This matters in practice: the default
  signing config still lists only `rekor.sigstore.dev` at major version 1, so signing
  against the public instance was out of reach while only v2 was implemented. Existing
  callers are unaffected — the constructor argument defaults to v2.
- v1 differences are handled inside the client: the verifier goes out as PEM and the
  digest as hex, the response is a map keyed by entry UUID, proof hashes are hex, and the
  entry carries an integrated time and a signed entry timestamp (the inclusion promise) —
  so a v1 bundle needs no separate RFC 3161 timestamp to be verifiable.
- `Verifier::pem()` renders the key or certificate the way v1 wants it.

## 1.0.0

First public release. A PSR-18 client for the Rekor v2 (rekor-tiles) transparency log.

- **`RekorClient::submitHashedRekord()`** — submits a hashedrekord entry (digest +
  signature + verifier) to `POST /api/v2/log/entries` and returns the
  `K2gl\SigstoreBundle\TransparencyLogEntry` Rekor integrated it as, ready to embed in a
  bundle with no translation. For a DSSE attestation, submit the PAE digest and the
  envelope signature (Rekor v2 has no DSSE entry type).
- **`Verifier`** — the signing identity a submission binds to: `publicKey()` (a bare key)
  or `certificate()` (a Fulcio keyless certificate), tagged with a **`KeyDetails`**
  algorithm.
- Transport is any PSR-18 client the caller supplies; the log base URL is required (it
  comes from the signing config, not hard-coded).
- Fail-closed parsing: a transport failure raises `RekorRequestException`, and an error
  status or an unparseable/malformed body raises `RekorResponseException` (carrying the
  HTTP status code).
- Scope is submission (the signer's write path). The tile-based read API is not covered
  yet; verifying an entry from a bundle is `k2gl/sigstore-verify`'s job.
