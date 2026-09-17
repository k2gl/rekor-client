<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Tests;

use K2gl\RekorClient\Exception\InvalidArgumentException;
use K2gl\RekorClient\Exception\RekorResponseException;
use K2gl\RekorClient\Internal\EntryBundle;
use K2gl\RekorClient\Internal\Http;
use K2gl\RekorClient\Internal\Json;
use K2gl\RekorClient\Internal\Merkle;
use K2gl\RekorClient\Internal\TilePath;
use K2gl\RekorClient\Internal\TileTree;
use K2gl\RekorClient\LogReader;
use K2gl\RekorClient\Tests\Support\FakeLog;
use K2gl\SigstoreBundle\BundleBuilder;
use K2gl\SigstoreBundle\HashAlgorithm;
use K2gl\SigstoreBundle\MessageSignature;
use K2gl\SigstoreBundle\TransparencyLogEntry;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(LogReader::class)]
#[CoversClass(TileTree::class)]
#[CoversClass(EntryBundle::class)]
#[CoversClass(Merkle::class)]
#[CoversClass(TilePath::class)]
#[CoversClass(Http::class)]
#[CoversClass(Json::class)]
#[CoversClass(RekorResponseException::class)]
final class LogReaderTest extends TestCase
{
    /** Three tile levels: 70 000 entries make 273 full level-0 tiles, one full level-1 tile, and partial tiles at every level. */
    private static ?FakeLog $bigLog = null;

    /** @var list<string> */
    private array $requested = [];

    #[TestWith([0])]
    #[TestWith([5])]
    #[TestWith([255])]
    #[TestWith([256])]
    #[TestWith([65535])]
    #[TestWith([65536])]
    #[TestWith([69999])]
    public function testReadsAnEntryWithAProofThatReproducesTheCheckpointRoot(int $index): void
    {
        $log = self::bigLog();

        $entry = $this->reader($log)->entry($index);

        fact($entry->logIndex)->is($index);
        fact($entry->canonicalizedBody)->is($log->bodies[$index]);
        fact($entry->kind)->is($index % 3 === 0 ? 'dsse' : 'hashedrekord');
        fact($entry->version)->is('0.0.2');
        fact($entry->integratedTime)->null();
        fact($entry->inclusionProof?->treeSize)->is(70000);
        fact($entry->inclusionProof?->rootHash)->is($log->rootHash);
        fact($entry->inclusionProof?->checkpoint)->is($log->checkpoint());
        fact(Merkle::rootFromPath(
            Merkle::leafHash($entry->canonicalizedBody),
            $index,
            70000,
            $entry->inclusionProof?->hashes ?? [],
        ))->is($log->rootHash);
    }

    public function testStampsEntriesWithTheNoteKeyHashAsTheLogId(): void
    {
        $log = self::bigLog();
        $raw = substr($log->publicKeyDer, -32);

        $entry = $this->reader($log)->entry(1);

        fact($entry->logId)->is(hash('sha256', FakeLog::ORIGIN . "\n\x01" . $raw, true));
        fact($entry->logId)->hasLength(32);
    }

    public function testAnEntryDropsStraightIntoABundle(): void
    {
        $entry = $this->reader(self::bigLog())->entry(300);

        $bundle = BundleBuilder::forMessageSignature(
            new MessageSignature(HashAlgorithm::SHA2_256, str_repeat("\x22", 32), 'sig'),
        )->withCertificate('fulcio-leaf-der')->addTransparencyLogEntry($entry)->toArray();

        fact($bundle['verificationMaterial']['tlogEntries'][0]['logIndex'])->is('300');
        fact($bundle['verificationMaterial']['tlogEntries'][0]['inclusionProof']['treeSize'])->is('70000');
    }

    public function testReadsARangeAcrossBundlesFromOneCheckpoint(): void
    {
        $log = self::bigLog();

        $entries = $this->reader($log)->entries(from: 250, count: 12);

        fact($entries)->count(12);
        fact(array_map(static fn (TransparencyLogEntry $e): int => $e->logIndex, $entries))->is(range(250, 261));
        fact(array_unique(array_map(static fn (TransparencyLogEntry $e): string => $e->inclusionProof?->checkpoint ?? '', $entries)))->count(1);
        fact(array_filter($this->requested, static fn (string $path): bool => $path === '/api/v2/checkpoint'))->count(1);
    }

    public function testARangeStopsAtTheHeadOfTheLog(): void
    {
        $reader = $this->reader(self::bigLog());

        fact($reader->entries(from: 69998, count: 10))->count(2);
        fact($reader->entries(from: 70000, count: 10))->is([]);
    }

    public function testReadsASmallLogWhoseEveryTileIsPartial(): void
    {
        $log = FakeLog::withEntries(3);

        $entry = $this->reader($log)->entry(2);

        fact($entry->inclusionProof?->treeSize)->is(3);
        fact(Merkle::rootFromPath(Merkle::leafHash($entry->canonicalizedBody), 2, 3, $entry->inclusionProof?->hashes ?? []))
            ->is($log->rootHash);
    }

    public function testReadsASingleEntryLog(): void
    {
        $log = FakeLog::withEntries(1);

        $entry = $this->reader($log)->entry(0);

        fact($entry->inclusionProof?->hashes)->is([]);
        fact($entry->inclusionProof?->rootHash)->is($log->rootHash);
    }

    public function testRefusesAnIndexTheLogHasNotReached(): void
    {
        // arrange
        $reader = $this->reader(FakeLog::withEntries(10));

        // act + assert
        fact(static fn () => $reader->entry(10))->throws(
            RekorResponseException::class,
            inspect: static fn (RekorResponseException $e) => fact($e->getMessage())->containsString('not in the log yet'),
        );
    }

    public function testTakesAFreshCheckpointWhenAPartialTileIsGone(): void
    {
        // arrange — the head moved from 300 to 310 entries between the checkpoint and the tiles
        $old = FakeLog::withEntries(300);
        $new = FakeLog::withEntries(310);
        $served = 0;
        $reader = $this->readerWith(function (RequestInterface $request) use ($old, $new, &$served): ResponseInterface {
            $path = $request->getUri()->getPath();

            if ($path === '/api/v2/checkpoint' && $served++ === 0) {
                return $old->respond($request);
            }

            return $new->respond($request);
        }, $new->publicKeyDer);

        // act
        $entry = $reader->entry(299);

        // assert
        fact($entry->inclusionProof?->treeSize)->is(310);
        fact($served)->is(2);
    }

    public function testDoesNotChaseTheHeadForever(): void
    {
        // arrange — every checkpoint is stale: no tile matches it
        $log = FakeLog::withEntries(300);
        $log->set(TilePath::tile(0, 1, 44), null);
        $reader = $this->reader($log);

        // act + assert
        fact(static fn () => $reader->entry(299))->throws(
            RekorResponseException::class,
            inspect: static fn (RekorResponseException $e) => fact($e->statusCode)->is(404),
        );
    }

    public function testRejectsACheckpointSignedByAnotherKey(): void
    {
        // arrange
        $log = FakeLog::withEntries(10);
        $reader = $this->readerWith($log->respond(...), (new FakeLog(['other'], str_repeat("\x09", 32)))->publicKeyDer);

        // act + assert
        fact(static fn () => $reader->checkpoint())->throws(
            RekorResponseException::class,
            inspect: static fn (RekorResponseException $e) => fact($e->getMessage())->containsString('not signed by the log key'),
        );
    }

    public function testRejectsACheckpointOfAnotherLog(): void
    {
        // arrange
        $log = FakeLog::withEntries(10);
        $reader = $this->readerWith($log->respond(...), $log->publicKeyDer, origin: 'some-other.log');

        // act + assert
        fact(static fn () => $reader->checkpoint())->throws(
            RekorResponseException::class,
            inspect: static fn (RekorResponseException $e) => fact($e->getMessage())->containsString('some-other.log'),
        );
    }

    public function testRejectsAMalformedCheckpoint(): void
    {
        // arrange
        $log = FakeLog::withEntries(10);
        $log->set('/api/v2/checkpoint', "just text\n\n");
        $reader = $this->reader($log);

        // act + assert
        fact(static fn () => $reader->checkpoint())->throws(RekorResponseException::class);
    }

    public function testRejectsTilesThatDoNotReproduceTheRoot(): void
    {
        // arrange — flip a hash in the level-1 tile
        $log = FakeLog::withEntries(300);
        $tile = $log->paths()[array_search(TilePath::tile(1, 0, 1), $log->paths(), true)];
        $log->set($tile, str_repeat("\x00", 32));
        $reader = $this->reader($log);

        // act + assert
        fact(static fn () => $reader->entry(299))->throws(
            RekorResponseException::class,
            inspect: static fn (RekorResponseException $e) => fact($e->getMessage())->containsString('do not reproduce the checkpoint root'),
        );
    }

    public function testRejectsATileOfTheWrongSize(): void
    {
        // arrange
        $log = FakeLog::withEntries(300);
        $log->set(TilePath::tile(0, 0, null), str_repeat("\x00", 8000));
        $reader = $this->reader($log);

        // act + assert
        fact(static fn () => $reader->entry(0))->throws(
            RekorResponseException::class,
            inspect: static fn (RekorResponseException $e) => fact($e->getMessage())->containsString('hashes wide'),
        );
    }

    public function testRejectsAnEntryBundleWithTheWrongCount(): void
    {
        // arrange
        $log = FakeLog::withEntries(3);
        $log->set(TilePath::entries(0, 3), pack('n', 2) . '{}');
        $reader = $this->reader($log);

        // act + assert
        fact(static fn () => $reader->entry(0))->throws(
            RekorResponseException::class,
            inspect: static fn (RekorResponseException $e) => fact($e->getMessage())->containsString('holds 1 entries'),
        );
    }

    public function testRejectsATruncatedEntryBundle(): void
    {
        // arrange
        $log = FakeLog::withEntries(3);
        $log->set(TilePath::entries(0, 3), pack('n', 50) . '{"short":true}');
        $reader = $this->reader($log);

        // act + assert
        fact(static fn () => $reader->entry(0))->throws(
            RekorResponseException::class,
            inspect: static fn (RekorResponseException $e) => fact($e->getMessage())->containsString('middle of an entry'),
        );
    }

    public function testRejectsAnEntryWithoutKindAndVersion(): void
    {
        // arrange
        $log = new FakeLog(['{"no":"kind"}']);
        $reader = $this->reader($log);

        // act + assert
        fact(static fn () => $reader->entry(0))->throws(RekorResponseException::class);
    }

    public function testRejectsBadArguments(): void
    {
        $log = FakeLog::withEntries(3);
        $reader = $this->reader($log);

        fact(static fn () => $reader->entry(-1))->throws(InvalidArgumentException::class);
        fact(static fn () => $reader->entries(0, 0))->throws(InvalidArgumentException::class);
        fact(fn () => $this->readerWith($log->respond(...), $log->publicKeyDer, origin: ''))->throws(InvalidArgumentException::class);
        fact(fn () => $this->readerWith($log->respond(...), ''))->throws(InvalidArgumentException::class);
        fact(fn () => $this->readerWith($log->respond(...), 'not a key'))->throws(InvalidArgumentException::class);
    }

    public function testDerivesTheLogIdOfAnEcdsaLogFromTheDerKey(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        fact($key)->notFalse();
        $pem = (string) openssl_pkey_get_details($key)['key'];
        $der = (string) base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);

        $reader = $this->readerWith(FakeLog::withEntries(1)->respond(...), $der);

        fact($reader->logId())->is(hash('sha256', $der, true));
    }

    private static function bigLog(): FakeLog
    {
        return self::$bigLog ??= FakeLog::withEntries(70000);
    }

    private function reader(FakeLog $log): LogReader
    {
        return $this->readerWith($log->respond(...), $log->publicKeyDer);
    }

    private function readerWith(callable $handler, string $publicKeyDer, string $origin = FakeLog::ORIGIN): LogReader
    {
        $http = $this->createStub(ClientInterface::class);
        $http->method('sendRequest')->willReturnCallback(function (RequestInterface $request) use ($handler): ResponseInterface {
            $this->requested[] = $request->getUri()->getPath();

            return $handler($request);
        });

        return new LogReader(
            httpClient: $http,
            requestFactory: new Psr17Factory,
            baseUrl: 'https://fake.rekor.example/',
            origin: $origin,
            publicKeyDer: $publicKeyDer,
            retries: 0,
        );
    }
}
