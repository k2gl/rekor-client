<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Tests;

use K2gl\RekorClient\Exception\InvalidArgumentException;
use K2gl\RekorClient\Exception\RekorRequestException;
use K2gl\RekorClient\Exception\RekorResponseException;
use K2gl\RekorClient\KeyDetails;
use K2gl\RekorClient\RekorApiVersion;
use K2gl\RekorClient\RekorClient;
use K2gl\RekorClient\Verifier;
use K2gl\SigstoreBundle\BundleBuilder;
use K2gl\SigstoreBundle\MessageSignature;
use K2gl\SigstoreBundle\HashAlgorithm;
use K2gl\SigstoreBundle\TransparencyLogEntry;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(RekorClient::class)]
#[CoversClass(RekorApiVersion::class)]
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
        // arrange
        $client = $this->client(function (): ResponseInterface {
            throw new class ('down') extends RuntimeException implements ClientExceptionInterface {};
        });

        // act + assert
        fact(static fn () => $client->submitHashedRekord(
            'd',
            's',
            Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256),
        ))->throws(RekorRequestException::class);
    }

    public function testNonJsonBodyThrowsResponseException(): void
    {
        // arrange
        $client = $this->client(fn (): ResponseInterface => $this->response(200, 'not json at all'));

        // act + assert
        fact(static fn () => $client->submitHashedRekord(
            'd',
            's',
            Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256),
        ))->throws(RekorResponseException::class);
    }

    public function testMalformedEntryThrowsResponseException(): void
    {
        // arrange
        $client = $this->client(fn (): ResponseInterface => $this->response(200, '{"logIndex":"5"}'));

        // act + assert
        fact(static fn () => $client->submitHashedRekord(
            'd',
            's',
            Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256),
        ))->throws(RekorResponseException::class);
    }

    public function testRejectsEmptyVerifierBytes(): void
    {
        // act + assert
        fact(static fn () => Verifier::publicKey('', KeyDetails::PKIX_ECDSA_P256_SHA_256))
            ->throws(\K2gl\RekorClient\Exception\InvalidArgumentException::class);
    }

    public function testSubmitsAHashedRekordToARekorV1Log(): void
    {
        // arrange
        $captured = null;
        $client = $this->client(
            function (RequestInterface $request) use (&$captured): ResponseInterface {
                $captured = $request;

                return $this->response(201, $this->fixture('rekor-v1-entry-response.json'));
            },
            RekorApiVersion::V1,
        );
        $digest = str_repeat("\x33", 32);

        // act
        $entry = $client->submitHashedRekord(
            digest: $digest,
            signature: 'raw-signature',
            verifier: Verifier::publicKey('der-public-key', KeyDetails::PKIX_ECDSA_P256_SHA_256),
        );

        // assert: v1 takes a proposed entry at its own path, hex digest and PEM key
        fact((string) $captured?->getUri())->is(self::BASE_URL . '/api/v1/log/entries');

        $sent = json_decode((string) $captured?->getBody(), true);
        fact($sent['kind'])->is('hashedrekord');
        fact($sent['apiVersion'])->is('0.0.1');
        fact($sent['spec']['data']['hash']['algorithm'])->is('sha256');
        fact($sent['spec']['data']['hash']['value'])->is(bin2hex($digest));
        fact($sent['spec']['signature']['content'])->is(base64_encode('raw-signature'));
        fact(base64_decode($sent['spec']['signature']['publicKey']['content'], true))
            ->is(Verifier::publicKey('der-public-key', KeyDetails::PKIX_ECDSA_P256_SHA_256)->pem());

        // assert: a real public-instance entry parses into the bundle type
        fact($entry->kind)->is('hashedrekord');
        fact($entry->version)->is('0.0.1');
        fact($entry->logIndex)->is(120000000);
        fact($entry->integratedTime)->is(1723232543);
        fact(bin2hex($entry->logId))->is('c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d');
        fact($entry->inclusionPromise)->notNull();
        fact($entry->inclusionProof?->treeSize)->is(117740831);
        fact($entry->inclusionProof?->hashes)->count(27);
        fact(strlen($entry->inclusionProof?->rootHash ?? ''))->is(32);
        fact(str_starts_with($entry->inclusionProof?->checkpoint ?? '', 'rekor.sigstore.dev - '))->true();
    }

    public function testRekorV1RequestMatchesTheShapeTheLogCanonicalises(): void
    {
        // arrange: the body Rekor echoes back is the canonicalised entry, so a real
        // public-instance entry is the reference for what a submission looks like
        $captured = null;
        $client = $this->client(
            function (RequestInterface $request) use (&$captured): ResponseInterface {
                $captured = $request;

                return $this->response(201, $this->fixture('rekor-v1-entry-response.json'));
            },
            RekorApiVersion::V1,
        );

        // act
        $entry = $client->submitHashedRekord(
            str_repeat("\x88", 32),
            'sig',
            Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256),
        );

        // assert
        $sent = json_decode((string) $captured?->getBody(), true);
        $canonical = json_decode($entry->canonicalizedBody, true);
        fact($this->leafKeys($sent))->is($this->leafKeys($canonical));
    }

    /**
     * @param  array<string, mixed> $data
     * @return list<string>
     */
    private function leafKeys(array $data, string $prefix = ''): array
    {
        $keys = [];

        foreach ($data as $key => $value) {
            $keys[] = $prefix . $key;

            if (is_array($value)) {
                $keys = [...$keys, ...$this->leafKeys($value, $prefix . $key . '.')];
            }
        }
        sort($keys);

        return $keys;
    }

    public function testRekorV1EntryDropsStraightIntoABundle(): void
    {
        // arrange
        $client = $this->client(
            fn (): ResponseInterface => $this->response(201, $this->fixture('rekor-v1-entry-response.json')),
            RekorApiVersion::V1,
        );

        // act
        $entry = $client->submitHashedRekord(
            digest: str_repeat("\x44", 32),
            signature: 'sig',
            verifier: Verifier::certificate('fulcio-leaf-der', KeyDetails::PKIX_ECDSA_P256_SHA_256),
        );
        $bundle = BundleBuilder::forMessageSignature(
            new MessageSignature(HashAlgorithm::SHA2_256, str_repeat("\x44", 32), 'sig'),
        )->withCertificate('fulcio-leaf-der')->addTransparencyLogEntry($entry)->toArray();

        // assert
        $tlog = $bundle['verificationMaterial']['tlogEntries'][0];
        fact($tlog['kindVersion'])->is(['kind' => 'hashedrekord', 'version' => '0.0.1']);
        fact($tlog['integratedTime'])->is('1723232543');
    }

    public function testRekorV1SendsACertificateVerifierAsACertificatePem(): void
    {
        // arrange
        $captured = null;
        $client = $this->client(
            function (RequestInterface $request) use (&$captured): ResponseInterface {
                $captured = $request;

                return $this->response(201, $this->fixture('rekor-v1-entry-response.json'));
            },
            RekorApiVersion::V1,
        );

        // act
        $client->submitHashedRekord(str_repeat("\x55", 32), 'sig', Verifier::certificate('leaf', KeyDetails::PKIX_ED25519));

        // assert
        $sent = json_decode((string) $captured?->getBody(), true);
        $pem = base64_decode($sent['spec']['signature']['publicKey']['content'], true);
        fact(str_starts_with((string) $pem, "-----BEGIN CERTIFICATE-----\n"))->true();
        fact(str_contains((string) $pem, base64_encode('leaf')))->true();
    }

    #[TestWith([31])]
    #[TestWith([33])]
    #[TestWith([20])]
    public function testRekorV1RejectsADigestThatIsNotSha2(int $length): void
    {
        // arrange
        $client = $this->client(
            fn (): ResponseInterface => $this->response(201, $this->fixture('rekor-v1-entry-response.json')),
            RekorApiVersion::V1,
        );

        // act + assert
        fact(fn () => $client->submitHashedRekord(
            str_repeat("\x66", $length),
            'sig',
            Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256),
        ))->throws(InvalidArgumentException::class);
    }

    public function testRekorV1RejectsAResponseThatIsNotASingleEntry(): void
    {
        // arrange
        $client = $this->client(
            fn (): ResponseInterface => $this->response(201, '{}'),
            RekorApiVersion::V1,
        );

        // act + assert
        fact(fn () => $client->submitHashedRekord(
            str_repeat("\x77", 32),
            'sig',
            Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256),
        ))->throws(RekorResponseException::class);
    }

    public function testRetriesAStatusTheLogUsesToSayBusy(): void
    {
        // arrange
        $attempts = 0;
        $client = $this->client(function () use (&$attempts): ResponseInterface {
            $attempts++;

            return $attempts < 3
                ? $this->response(503, '{"message":"reached max pushback; retry"}')
                : $this->response(201, $this->fixture('rekor-v2-entry-response.json'));
        });

        // act
        $entry = $client->submitHashedRekord(str_repeat("\x11", 32), 'sig', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256));

        // assert
        fact($attempts)->is(3);
        fact($entry->logIndex)->is(735);
        fact(count($this->slept))->is(2);
        fact($this->slept[1] > $this->slept[0])->true();
    }

    public function testRetriesTheCancellationSeenOnTheRealLog(): void
    {
        // arrange: the failure that turned a conformance run red — the log
        // cancelled the request server-side
        $attempts = 0;
        $client = $this->client(function () use (&$attempts): ResponseInterface {
            $attempts++;

            return $attempts === 1
                ? $this->response(499, '{"code":1, "message":"add entry: await: context canceled", "details":[]}')
                : $this->response(201, $this->fixture('rekor-v2-entry-response.json'));
        });

        // act
        $entry = $client->submitHashedRekord(str_repeat("\x11", 32), 'sig', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256));

        // assert
        fact($attempts)->is(2);
        fact($entry->kind)->is('hashedrekord');
    }

    public function testRetriesATransportFailure(): void
    {
        // arrange
        $attempts = 0;
        $client = $this->client(function () use (&$attempts): ResponseInterface {
            $attempts++;

            if ($attempts === 1) {
                throw new class ('connection reset') extends RuntimeException implements ClientExceptionInterface {};
            }

            return $this->response(201, $this->fixture('rekor-v2-entry-response.json'));
        });

        // act
        $entry = $client->submitHashedRekord(str_repeat("\x11", 32), 'sig', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256));

        // assert
        fact($attempts)->is(2);
        fact($entry->logIndex)->is(735);
    }

    public function testDoesNotRetryARejectedEntry(): void
    {
        // arrange
        $attempts = 0;
        $client = $this->client(function () use (&$attempts): ResponseInterface {
            $attempts++;

            return $this->response(400, '{"message":"invalid entry"}');
        });

        // act + assert
        fact(fn () => $client->submitHashedRekord(str_repeat("\x11", 32), 'sig', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256)))
            ->throws(RekorResponseException::class);
        fact($attempts)->is(1);
        fact($this->slept)->is([]);
    }

    public function testGivesUpAfterTheConfiguredNumberOfAttempts(): void
    {
        // arrange
        $attempts = 0;
        $client = $this->client(function () use (&$attempts): ResponseInterface {
            $attempts++;

            return $this->response(503, '');
        });

        // act + assert
        fact(fn () => $client->submitHashedRekord(str_repeat("\x11", 32), 'sig', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256)))
            ->throws(RekorResponseException::class);
        fact($attempts)->is(3);
    }

    public function testSendsOnceWhenRetriesAreTurnedOff(): void
    {
        // arrange
        $attempts = 0;
        $client = $this->client(
            function () use (&$attempts): ResponseInterface {
                $attempts++;

                return $this->response(503, '');
            },
            retries: 0,
        );

        // act + assert
        fact(fn () => $client->submitHashedRekord(str_repeat("\x11", 32), 'sig', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256)))
            ->throws(RekorResponseException::class);
        fact($attempts)->is(1);
    }

    public function testWaitsAsLongAsTheLogAsked(): void
    {
        // arrange
        $attempts = 0;
        $client = $this->client(function () use (&$attempts): ResponseInterface {
            $attempts++;

            return $attempts === 1
                ? $this->response(429, '', ['Retry-After' => '3'])
                : $this->response(201, $this->fixture('rekor-v2-entry-response.json'));
        });

        // act
        $client->submitHashedRekord(str_repeat("\x11", 32), 'sig', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256));

        // assert
        fact($this->slept)->is([3_000_000]);
    }

    public function testRekorV1FollowsAConflictToTheEntryAlreadyLogged(): void
    {
        // arrange: this is what a retry meets when the first attempt reached the
        // log but its answer did not come back
        $uuid = str_repeat('a', 64);
        $paths = [];
        $client = $this->client(
            function (RequestInterface $request) use (&$paths, $uuid): ResponseInterface {
                $paths[] = $request->getUri()->getPath();

                return count($paths) === 1
                    ? $this->response(409, '{"message":"entry already exists"}', [
                        'Location' => '/api/v1/log/entries/' . $uuid,
                    ])
                    : $this->response(200, $this->fixture('rekor-v1-entry-response.json'));
            },
            RekorApiVersion::V1,
        );

        // act
        $entry = $client->submitHashedRekord(str_repeat("\x11", 32), 'sig', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256));

        // assert
        fact($paths)->is(['/api/v1/log/entries', '/api/v1/log/entries/' . $uuid]);
        fact($entry->logIndex)->is(120000000);
    }

    public function testRekorV1ConflictWithoutAUsableLocationIsReported(): void
    {
        // arrange
        $client = $this->client(
            fn (): ResponseInterface => $this->response(409, '{"message":"entry already exists"}'),
            RekorApiVersion::V1,
        );

        // act + assert
        fact(fn () => $client->submitHashedRekord(str_repeat("\x11", 32), 'sig', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256)))
            ->throws(RekorResponseException::class, 'no usable Location');
    }

    public function testRekorV2ConflictNamesTheEntryAlreadyLogged(): void
    {
        // arrange
        $client = $this->client(fn (): ResponseInterface => $this->response(
            409,
            '{"message":"entry already exists"}',
            ['x-log-index' => '4242'],
        ));

        // act + assert
        fact(fn () => $client->submitHashedRekord(str_repeat("\x11", 32), 'sig', Verifier::publicKey('k', KeyDetails::PKIX_ECDSA_P256_SHA_256)))
            ->throws(RekorResponseException::class, 'log index 4242');
    }

    /** Microsecond delays the client asked for, newest last. @var list<int> */
    private array $slept = [];

    /** @param callable(RequestInterface): ResponseInterface $handler */
    private function client(
        callable $handler,
        RekorApiVersion $apiVersion = RekorApiVersion::V2,
        int $retries = 2,
    ): RekorClient {
        $psr17 = new Psr17Factory;
        $http = $this->createMock(ClientInterface::class);
        $http->method('sendRequest')->willReturnCallback($handler);
        $this->slept = [];

        return new RekorClient(
            $http,
            $psr17,
            $psr17,
            self::BASE_URL,
            $apiVersion,
            $retries,
            function (int $microseconds): void {
                $this->slept[] = $microseconds;
            },
        );
    }

    /** @param array<string, string> $headers */
    private function response(int $status, string $body, array $headers = []): ResponseInterface
    {
        $response = (new Psr17Factory)->createResponse($status)
            ->withBody((new Psr17Factory)->createStream($body));

        foreach ($headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    private function fixture(string $name): string
    {
        $contents = file_get_contents(__DIR__ . '/fixtures/' . $name);
        fact($contents)->isString();

        return $contents;
    }
}
