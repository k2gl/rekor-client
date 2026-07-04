<?php

declare(strict_types=1);

namespace K2gl\RekorClient;

use JsonException;
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
 * A client for a Rekor v2 (rekor-tiles) transparency log. It submits a
 * hashedrekord entry and hands back the {@see TransparencyLogEntry} Rekor
 * returns — the same value {@see \K2gl\SigstoreBundle\BundleBuilder} takes, so a
 * signer can go submit → add-to-bundle without a translation layer.
 *
 * Transport is any PSR-18 client the caller supplies; this package speaks the
 * Rekor API but owns no socket. The log's base URL is required (Sigstore
 * distributes it in the signing config; it is not hard-coded here).
 *
 * @see https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md
 */
final class RekorClient
{
    private readonly string $baseUrl;

    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        string $baseUrl,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * Submit a hashedrekord entry (digest + signature + verifier) and return the
     * transparency-log entry Rekor integrated it as. For a DSSE attestation,
     * pass the digest of the PAE and the envelope signature (Rekor v2 has no
     * DSSE entry type; it records the PAE as a hashedrekord).
     *
     * @param string $digest    raw digest bytes the signature is over
     * @param string $signature raw signature bytes
     */
    public function submitHashedRekord(string $digest, string $signature, Verifier $verifier): TransparencyLogEntry
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

        return $this->parseEntry($this->post('/api/v2/log/entries', $body));
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
    private function parseEntry(array $entry): TransparencyLogEntry
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
            inclusionProof: $this->parseInclusionProof($entry),
        );
    }

    /** @param array<string, mixed> $entry */
    private function parseInclusionProof(array $entry): ?InclusionProof
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
}
