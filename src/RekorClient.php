<?php

declare(strict_types=1);

namespace K2gl\RekorClient;

use Closure;
use JsonException;
use K2gl\RekorClient\Exception\InvalidArgumentException;
use K2gl\RekorClient\Exception\RekorResponseException;
use K2gl\RekorClient\Internal\Http;
use K2gl\RekorClient\Internal\Json;
use K2gl\SigstoreBundle\InclusionProof;
use K2gl\SigstoreBundle\TransparencyLogEntry;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * A client for a Rekor transparency log. It submits a hashedrekord entry and
 * hands back the {@see TransparencyLogEntry} Rekor returns — the same value
 * {@see \K2gl\SigstoreBundle\BundleBuilder} takes, so a signer can go
 * submit → add-to-bundle without a translation layer.
 *
 * Both major versions are spoken. They differ in more than the path: v1 takes
 * the key as PEM and the digest as hex, answers with a map keyed by entry UUID,
 * hex-encodes hashes and gives every entry an integrated time and a signed entry
 * timestamp; v2 takes raw DER and base64, answers with the entry itself and
 * leaves timestamping to a TSA. {@see RekorApiVersion} covers which is which —
 * take it from the log's `majorApiVersion` in the signing config, as Sigstore's
 * default config still points at a v1 log.
 *
 * Transport is any PSR-18 client the caller supplies; this package speaks the
 * Rekor API but owns no socket. The log's base URL is required (Sigstore
 * distributes it in the signing config; it is not hard-coded here). Reading
 * entries back out of a v2 log is {@see LogReader}'s job.
 *
 * @see https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md
 * @see https://github.com/sigstore/rekor/blob/main/openapi.yaml
 */
final class RekorClient
{
    /** Extra attempts after the first one. */
    private const DEFAULT_RETRIES = Http::DEFAULT_RETRIES;

    private readonly Http $http;

    public function __construct(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory,
        string $baseUrl,
        private readonly RekorApiVersion $apiVersion = RekorApiVersion::V2,
        int $retries = self::DEFAULT_RETRIES,
        ?Closure $sleeper = null,
    ) {
        $this->http = new Http($httpClient, $requestFactory, $baseUrl, $streamFactory, $retries, $sleeper);
    }

    /**
     * Submit a hashedrekord entry (digest + signature + verifier) and return the
     * transparency-log entry Rekor integrated it as. For a DSSE attestation,
     * pass the digest of the PAE and the envelope signature: this client submits
     * hashedrekord entries, and that is what a DSSE bundle carries.
     *
     * @param string $digest    raw digest bytes the signature is over
     * @param string $signature raw signature bytes
     */
    public function submitHashedRekord(string $digest, string $signature, Verifier $verifier): TransparencyLogEntry
    {
        return match ($this->apiVersion) {
            RekorApiVersion::V1 => $this->submitV1($digest, $signature, $verifier),
            RekorApiVersion::V2 => $this->submitV2($digest, $signature, $verifier),
        };
    }

    private function submitV2(string $digest, string $signature, Verifier $verifier): TransparencyLogEntry
    {
        $body = [
            'hashedRekordRequestV002' => [
                'digest' => base64_encode($digest),
                'signature' => [
                    'content' => base64_encode($signature),
                    'verifier' => $verifier->toArray(),
                ],
            ],
        ];

        $response = $this->http->postJson('/api/v2/log/entries', $body);

        if ($response->getStatusCode() === 409) {
            // rekor-tiles reports a duplicate as AlreadyExists and names the entry
            // in x-log-index. There is no write-side endpoint to read it back, so
            // say where it is and let the caller fetch it from the read path.
            throw new RekorResponseException(
                sprintf(
                    'Rekor already holds this entry%s.',
                    $response->hasHeader('x-log-index')
                        ? ' at log index ' . $response->getHeaderLine('x-log-index')
                        : '',
                ),
                statusCode: 409,
            );
        }

        return $this->parseV2Entry($this->decode($response));
    }

    private function submitV1(string $digest, string $signature, Verifier $verifier): TransparencyLogEntry
    {
        $body = [
            'apiVersion' => '0.0.1',
            'kind' => 'hashedrekord',
            'spec' => [
                'data' => [
                    'hash' => [
                        'algorithm' => self::hashAlgorithm($digest),
                        'value' => bin2hex($digest),
                    ],
                ],
                'signature' => [
                    'content' => base64_encode($signature),
                    'publicKey' => ['content' => base64_encode($verifier->pem())],
                ],
            ],
        ];

        $response = $this->http->postJson('/api/v1/log/entries', $body);

        // A duplicate is not a failure: the entry is in the log, and Rekor points
        // at it. This is also what a retry runs into when the first attempt
        // reached the log but its answer did not reach us.
        if ($response->getStatusCode() === 409) {
            $response = $this->fetchExistingV1Entry($response);
        }

        return $this->parseV1Entry($this->decode($response));
    }

    /** The hashedrekord 0.0.1 algorithm name for a digest, by its length. */
    private static function hashAlgorithm(string $digest): string
    {
        return match (strlen($digest)) {
            32 => 'sha256',
            48 => 'sha384',
            64 => 'sha512',
            default => throw new InvalidArgumentException(sprintf(
                'A Rekor v1 hashedrekord takes a SHA-256, SHA-384 or SHA-512 digest; got %d bytes.',
                strlen($digest),
            )),
        };
    }

    /**
     * Rekor v1 answers a duplicate with 409 and a Location pointing at the entry
     * that is already there. Follow it.
     */
    private function fetchExistingV1Entry(ResponseInterface $conflict): ResponseInterface
    {
        $location = trim($conflict->getHeaderLine('Location'));
        $uuid = $location === '' ? '' : basename(parse_url($location, PHP_URL_PATH) ?: '');

        if ($uuid === '' || preg_match('/^[0-9a-f]{64,80}$/', $uuid) !== 1) {
            throw new RekorResponseException(
                'Rekor reported the entry as already logged but gave no usable Location for it.',
                statusCode: 409,
            );
        }

        return $this->http->get('/api/v1/log/entries/' . $uuid);
    }

    /**
     * Check the status and decode the JSON body.
     *
     * @return array<string, mixed>
     */
    private function decode(ResponseInterface $response): array
    {
        $status = $response->getStatusCode();
        $payload = (string) $response->getBody();

        if ($status < 200 || $status >= 300) {
            throw new RekorResponseException(
                sprintf('Rekor returned HTTP %d: %s', $status, trim($payload) === '' ? '(empty body)' : trim($payload)),
                statusCode: $status,
            );
        }

        try {
            $decoded = json_decode($payload, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RekorResponseException('Rekor response was not valid JSON: ' . $e->getMessage());
        }

        if (! is_array($decoded)) {
            throw new RekorResponseException('Rekor response was not a JSON object.');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /** @param array<string, mixed> $entry */
    private function parseV2Entry(array $entry): TransparencyLogEntry
    {
        $kindVersion = Json::object($entry, 'kindVersion');
        $integratedTime = isset($entry['integratedTime']) ? Json::intString($entry, 'integratedTime') : 0;

        return new TransparencyLogEntry(
            logIndex: Json::intString($entry, 'logIndex'),
            logId: Json::base64(Json::object($entry, 'logId'), 'keyId'),
            kind: Json::string($kindVersion, 'kind'),
            version: Json::string($kindVersion, 'version'),
            canonicalizedBody: Json::base64($entry, 'canonicalizedBody'),
            // Rekor v2 integrates entries without a per-entry time (it returns 0); keep null then.
            integratedTime: $integratedTime !== 0 ? $integratedTime : null,
            inclusionProof: $this->parseV2InclusionProof($entry),
        );
    }

    /** @param array<string, mixed> $entry */
    private function parseV2InclusionProof(array $entry): ?InclusionProof
    {
        if (! isset($entry['inclusionProof'])) {
            return null;
        }
        $proof = Json::object($entry, 'inclusionProof');

        return new InclusionProof(
            logIndex: Json::intString($proof, 'logIndex'),
            rootHash: Json::base64($proof, 'rootHash'),
            treeSize: Json::intString($proof, 'treeSize'),
            hashes: Json::base64List($proof, 'hashes'),
            checkpoint: Json::string(Json::object($proof, 'checkpoint'), 'envelope'),
        );
    }

    /**
     * Rekor v1 answers with a map of entry UUID => entry, and a submission
     * creates exactly one.
     *
     * @param array<string, mixed> $response
     */
    private function parseV1Entry(array $response): TransparencyLogEntry
    {
        if (count($response) !== 1) {
            throw new RekorResponseException(sprintf(
                'Expected the Rekor response to hold exactly one entry, got %d.',
                count($response),
            ));
        }
        $entry = reset($response);

        if (! is_array($entry)) {
            throw new RekorResponseException('The Rekor entry was not a JSON object.');
        }

        /** @var array<string, mixed> $entry */
        $canonicalizedBody = Json::base64($entry, 'body');
        $verification = isset($entry['verification']) ? Json::object($entry, 'verification') : [];
        [$kind, $version] = Json::kindVersion($canonicalizedBody);

        return new TransparencyLogEntry(
            logIndex: Json::intString($entry, 'logIndex'),
            logId: Json::hex($entry, 'logID'),
            kind: $kind,
            version: $version,
            canonicalizedBody: $canonicalizedBody,
            integratedTime: Json::intString($entry, 'integratedTime'),
            inclusionPromise: isset($verification['signedEntryTimestamp'])
                ? Json::base64($verification, 'signedEntryTimestamp')
                : null,
            inclusionProof: $this->parseV1InclusionProof($verification),
        );
    }

    /** @param array<string, mixed> $verification */
    private function parseV1InclusionProof(array $verification): ?InclusionProof
    {
        if (! isset($verification['inclusionProof'])) {
            return null;
        }
        $proof = Json::object($verification, 'inclusionProof');

        return new InclusionProof(
            logIndex: Json::intString($proof, 'logIndex'),
            rootHash: Json::hex($proof, 'rootHash'),
            treeSize: Json::intString($proof, 'treeSize'),
            hashes: Json::hexList($proof, 'hashes'),
            checkpoint: Json::string($proof, 'checkpoint'),
        );
    }
}
