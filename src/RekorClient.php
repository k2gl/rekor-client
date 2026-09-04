<?php

declare(strict_types=1);

namespace K2gl\RekorClient;

use JsonException;
use K2gl\RekorClient\Exception\InvalidArgumentException;
use K2gl\RekorClient\Exception\RekorRequestException;
use K2gl\RekorClient\Exception\RekorResponseException;
use K2gl\RekorClient\Internal\Json;
use K2gl\SigstoreBundle\InclusionProof;
use K2gl\SigstoreBundle\TransparencyLogEntry;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
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
 * distributes it in the signing config; it is not hard-coded here).
 *
 * @see https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md
 * @see https://github.com/sigstore/rekor/blob/main/openapi.yaml
 */
final class RekorClient
{
    private readonly string $baseUrl;

    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        string $baseUrl,
        private readonly RekorApiVersion $apiVersion = RekorApiVersion::V2,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * Submit a hashedrekord entry (digest + signature + verifier) and return the
     * transparency-log entry Rekor integrated it as. For a DSSE attestation,
     * pass the digest of the PAE and the envelope signature (neither version has
     * a DSSE entry type here; the PAE goes in as a hashedrekord).
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

        return $this->parseV2Entry($this->post('/api/v2/log/entries', $body));
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

        return $this->parseV1Entry($this->post('/api/v1/log/entries', $body));
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
     * POST a JSON body and return the decoded response object.
     *
     * @param  array<string, mixed> $body
     * @return array<string, mixed>
     */
    private function post(string $path, array $body): array
    {
        try {
            $json = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new RekorRequestException('Could not encode the Rekor request body: ' . $e->getMessage(), previous: $e);
        }

        $request = $this->requestFactory->createRequest('POST', $this->baseUrl . $path)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($json));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new RekorRequestException('Rekor request failed: ' . $e->getMessage(), previous: $e);
        }
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
        [$kind, $version] = self::kindVersion($canonicalizedBody);

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

    /**
     * v1 does not report the entry kind alongside the entry — it is inside the
     * canonical body it echoes back.
     *
     * @return array{0: string, 1: string}
     */
    private static function kindVersion(string $canonicalizedBody): array
    {
        try {
            /** @var mixed $decoded */
            $decoded = json_decode($canonicalizedBody, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RekorResponseException('The Rekor entry body is not valid JSON: ' . $e->getMessage());
        }

        if (! is_array($decoded)) {
            throw new RekorResponseException('The Rekor entry body is not a JSON object.');
        }

        /** @var array<string, mixed> $decoded */
        return [Json::string($decoded, 'kind'), Json::string($decoded, 'apiVersion')];
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
