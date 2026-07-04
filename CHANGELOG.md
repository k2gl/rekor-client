# Changelog

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
