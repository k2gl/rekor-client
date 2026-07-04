<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Tests;

use K2gl\RekorClient\Exception\RekorRequestException;
use K2gl\RekorClient\Exception\RekorResponseException;
use K2gl\RekorClient\KeyDetails;
use K2gl\RekorClient\RekorClient;
use K2gl\RekorClient\Verifier;
use K2gl\SigstoreBundle\BundleBuilder;
use K2gl\SigstoreBundle\MessageSignature;
use K2gl\SigstoreBundle\HashAlgorithm;
use K2gl\SigstoreBundle\TransparencyLogEntry;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(RekorClient::class)]
#[CoversClass(Verifier::class)]
#[CoversClass(KeyDetails::class)]
#[CoversClass(\K2gl\RekorClient\Internal\Json::class)]
#[CoversClass(RekorResponseException::class)]
#[CoversClass(RekorRequestException::class)]
final class RekorClientTest extends TestCase
{
    private const BASE_URL = 'https://log2026.rekor.sigstore.dev';

    public function testSubmitBuildsTheRequestAndParsesTheEntry(): void
    {
        $captured = null;
        $client = $this->client(function (RequestInterface $request) use (&$captured): ResponseInterface {
            $captured = $request;

            return $this->response(200, $this->fixture('rekor-v2-entry-response.json'));
        });

        $entry = $client->submitHashedRekord(
            digest: str_repeat("\x11", 32),
            signature: 'raw-signature',
            verifier: Verifier::publicKey('der-public-key', KeyDetails::PKIX_ECDSA_P256_SHA_256),
        );

        // The request went where and how Rekor v2 expects.
        fact($captured?->getMethod())->is('POST');
        fact((string) $captured?->getUri())->is(self::BASE_URL . '/api/v2/log/entries');
        fact($captured?->getHeaderLine('Content-Type'))->is('application/json');

        $sent = json_decode((string) $captured?->getBody(), true);
        fact($sent['hashedRekordRequestV002']['digest'])->is(base64_encode(str_repeat("\x11", 32)));
        fact($sent['hashedRekordRequestV002']['signature']['content'])->is(base64_encode('raw-signature'));
        fact($sent['hashedRekordRequestV002']['signature']['verifier']['keyDetails'])->is('PKIX_ECDSA_P256_SHA_256');
        fact($sent['hashedRekordRequestV002']['signature']['verifier']['publicKey']['rawBytes'])->is(base64_encode('der-public-key'));

        // The parsed entry is a real bundle TransparencyLogEntry, ready to embed.
        fact($entry)->instanceOf(TransparencyLogEntry::class);
        fact($entry->kind)->is('hashedrekord');
        fact($entry->version)->is('0.0.2');
        fact($entry->logIndex)->is(735);
        fact($entry->inclusionProof)->notNull();
    }

    public function testReturnedEntryDropsStraightIntoABundle(): void
    {
        $client = $this->client(fn (): ResponseInterface => $this->response(201, $this->fixture('rekor-v2-entry-response.json')));

        $entry = $client->submitHashedRekord(
            digest: str_repeat("\x22", 32),
            signature: 'sig',
            verifier: Verifier::certificate('fulcio-leaf-der', KeyDetails::PKIX_ECDSA_P256_SHA_256),
        );

        $bundle = BundleBuilder::forMessageSignature(
            new MessageSignature(HashAlgorithm::SHA2_256, str_repeat("\x22", 32), 'sig'),
        )->withCertificate('fulcio-leaf-der')->addTransparencyLogEntry($entry)->toArray();

        fact($bundle['verificationMaterial']['tlogEntries'][0]['kindVersion']['kind'])->is('hashedrekord');
    }

    public function testCertificateVerifierIsSentAsX509(): void
    {
        $captured = null;
        $client = $this->client(function (RequestInterface $request) use (&$captured): ResponseInterface {
            $captured = $request;

            return $this->response(200, $this->fixture('rekor-v2-entry-response.json'));
        });

        $client->submitHashedRekord('d', 's', Verifier::certificate('leaf', KeyDetails::PKIX_ED25519));

        $sent = json_decode((string) $captured?->getBody(), true);
        fact($sent['hashedRekordRequestV002']['signature']['verifier']['x509Certificate']['rawBytes'])->is(base64_encode('leaf'));
        fact(isset($sent['hashedRekordRequestV002']['signature']['verifier']['publicKey']))->false();
    }

    public function testErrorStatusThrowsResponseException(): void
    {
        $client = $this->client(fn (): ResponseInterface => $this->response(409, '{"message":"entry already exists"}'));

        try {
            $client->submitHashedRekord('d', 's', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256));
            self::fail('Expected a RekorResponseException.');
        } catch (RekorResponseException $e) {
            fact($e->statusCode)->is(409);
        }
    }

    public function testTransportErrorThrowsRequestException(): void
    {
        $client = $this->client(function (): ResponseInterface {
            throw new class ('down') extends RuntimeException implements ClientExceptionInterface {};
        });

        $this->expectException(RekorRequestException::class);
        $client->submitHashedRekord('d', 's', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256));
    }

    public function testNonJsonBodyThrowsResponseException(): void
    {
        $client = $this->client(fn (): ResponseInterface => $this->response(200, 'not json at all'));

        $this->expectException(RekorResponseException::class);
        $client->submitHashedRekord('d', 's', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256));
    }

    public function testMalformedEntryThrowsResponseException(): void
    {
        $client = $this->client(fn (): ResponseInterface => $this->response(200, '{"logIndex":"5"}'));

        $this->expectException(RekorResponseException::class);
        $client->submitHashedRekord('d', 's', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256));
    }

    public function testRejectsEmptyVerifierBytes(): void
    {
        $this->expectException(\K2gl\RekorClient\Exception\InvalidArgumentException::class);
        Verifier::publicKey('', KeyDetails::PKIX_ECDSA_P256_SHA_256);
    }

    /** @param callable(RequestInterface): ResponseInterface $handler */
    private function client(callable $handler): RekorClient
    {
        $psr17 = new Psr17Factory;
        $http = $this->createMock(ClientInterface::class);
        $http->method('sendRequest')->willReturnCallback($handler);

        return new RekorClient($http, $psr17, $psr17, self::BASE_URL);
    }

    private function response(int $status, string $body): ResponseInterface
    {
        return (new Psr17Factory)->createResponse($status)->withBody((new Psr17Factory)->createStream($body));
    }

    private function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/' . $name);
        fact($contents)->isString();

        return $contents;
    }
}
