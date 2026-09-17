<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Tests;

use K2gl\RekorClient\Internal\EntryBundle;
use K2gl\RekorClient\Internal\Http;
use K2gl\RekorClient\Internal\Json;
use K2gl\RekorClient\Internal\Merkle;
use K2gl\RekorClient\Internal\TilePath;
use K2gl\RekorClient\Internal\TileTree;
use K2gl\RekorClient\LogReader;
use K2gl\SignedNote\Checkpoint;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * A slice of the public Rekor v2 log as it was served (tests/fixtures/rekor-v2,
 * recorded by record.php): the checkpoint, the head entry bundle and the four
 * partial tiles the head entry's proof runs through.
 */
#[CoversClass(LogReader::class)]
#[CoversClass(TileTree::class)]
#[CoversClass(EntryBundle::class)]
#[CoversClass(Merkle::class)]
#[CoversClass(TilePath::class)]
#[CoversClass(Http::class)]
#[CoversClass(Json::class)]
final class RecordedLogTest extends TestCase
{
    /** The log id Sigstore's trusted root lists for log2025-1.rekor.sigstore.dev. */
    private const TRUSTED_ROOT_LOG_ID = 'cf1199155bddd051268d1f16ac5c0c75c009f6fb5a63f4177f8e18d7051e3fa0';

    public function testReadsTheHeadEntryOfThePublicLogWithAProofToItsCheckpoint(): void
    {
        // arrange
        $manifest = $this->manifest();
        $reader = $this->reader($manifest);
        $checkpoint = Checkpoint::parse($this->file($manifest, '/api/v2/checkpoint'));
        $logIndex = (int) $manifest['logIndex'];

        // act
        $entry = $reader->entry($logIndex);

        // assert
        fact($entry->logIndex)->is($logIndex);
        fact(bin2hex($entry->logId))->is(self::TRUSTED_ROOT_LOG_ID);
        fact(['hashedrekord', 'dsse'])->contains($entry->kind);
        fact($entry->version)->is('0.0.2');
        fact($entry->canonicalizedBody)->startsWith('{"apiVersion":"0.0.2","kind":"');
        fact($entry->inclusionProof?->treeSize)->is($checkpoint->treeSize);
        fact($entry->inclusionProof?->rootHash)->is($checkpoint->rootHash);
        fact($entry->inclusionProof?->checkpoint)->is((string) $checkpoint);
        fact($entry->inclusionProof?->hashes)->count(self::pathLength($logIndex, $checkpoint->treeSize));
        fact(Merkle::rootFromPath(
            Merkle::leafHash($entry->canonicalizedBody),
            $logIndex,
            $checkpoint->treeSize,
            $entry->inclusionProof?->hashes ?? [],
        ))->is($checkpoint->rootHash);
    }

    public function testTheCheckpointVerifiesWithTheKeyFromTheTrustedRoot(): void
    {
        $manifest = $this->manifest();

        $checkpoint = $this->reader($manifest)->checkpoint();

        fact($checkpoint->origin)->is('log2025-1.rekor.sigstore.dev');
        fact($checkpoint->treeSize)->is(114109027);
    }

    /** How many siblings an RFC 9162 inclusion path has: the inner nodes below the fork, plus one per left subtree above it. */
    private static function pathLength(int $index, int $treeSize): int
    {
        $inner = strlen(decbin($index ^ ($treeSize - 1))) - (($index ^ ($treeSize - 1)) === 0 ? 1 : 0);
        $border = substr_count(decbin($index >> $inner), '1');

        return $inner + $border;
    }

    /** @return array{origin: string, publicKeyDer: string, logIndex: int, files: array<string, string>} */
    private function manifest(): array
    {
        $json = file_get_contents(__DIR__ . '/fixtures/rekor-v2/manifest.json');
        fact($json)->isString();

        /** @var array{origin: string, publicKeyDer: string, logIndex: int, files: array<string, string>} */
        return json_decode((string) $json, true, flags: JSON_THROW_ON_ERROR);
    }

    /** @param array{files: array<string, string>} $manifest */
    private function file(array $manifest, string $path): string
    {
        $bytes = file_get_contents(__DIR__ . '/fixtures/rekor-v2/' . $manifest['files'][$path]);
        fact($bytes)->isString();

        return (string) $bytes;
    }

    /** @param array{origin: string, publicKeyDer: string, files: array<string, string>} $manifest */
    private function reader(array $manifest): LogReader
    {
        $http = $this->createStub(ClientInterface::class);
        $http->method('sendRequest')->willReturnCallback(function (RequestInterface $request) use ($manifest): ResponseInterface {
            $factory = new Psr17Factory;
            $path = $request->getUri()->getPath();

            if (! isset($manifest['files'][$path])) {
                return $factory->createResponse(404)->withBody($factory->createStream('not recorded: ' . $path));
            }

            return $factory->createResponse(200)->withBody($factory->createStream($this->file($manifest, $path)));
        });

        return new LogReader(
            httpClient: $http,
            requestFactory: new Psr17Factory,
            baseUrl: 'https://' . $manifest['origin'],
            origin: $manifest['origin'],
            publicKeyDer: (string) base64_decode($manifest['publicKeyDer'], true),
            retries: 0,
        );
    }
}
