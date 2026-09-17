<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Tests\Support;

use K2gl\RekorClient\Internal\Merkle;
use K2gl\RekorClient\Internal\TilePath;
use K2gl\SignedNote\Internal\NoteKey;
use K2gl\SignedNote\SignerKey;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A tiled log built in memory the way a real one is laid out on disk: hash
 * tiles at every level (full ones and the partial one at the head), entry
 * bundles, and a checkpoint signed with an Ed25519 key. The tree is assembled
 * by plain RFC 6962 recursion, independently of the reader's tile arithmetic.
 */
final class FakeLog
{
    public const ORIGIN = 'fake.rekor.example';

    private const ED25519_SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    public readonly string $publicKeyDer;

    public readonly string $rootHash;

    private readonly SignerKey $signer;

    /** @var array<string, string> path => bytes */
    private array $files = [];

    /** @param list<string> $bodies */
    public function __construct(public readonly array $bodies, string $seed = "\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07")
    {
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $public = sodium_crypto_sign_publickey($keypair);
        $hash = NoteKey::hash(self::ORIGIN, chr(NoteKey::ALG_ED25519) . $public);
        $this->signer = SignerKey::fromString(
            'PRIVATE+KEY+' . self::ORIGIN . '+' . bin2hex($hash) . '+' . base64_encode(chr(NoteKey::ALG_ED25519) . $seed),
        );
        $this->publicKeyDer = self::ED25519_SPKI_PREFIX . $public;
        $this->rootHash = self::mth(array_map(Merkle::leafHash(...), $bodies));
        $this->build();
    }

    public static function withEntries(int $count): self
    {
        $bodies = [];

        for ($i = 0; $i < $count; $i++) {
            $bodies[] = json_encode([
                'apiVersion' => '0.0.2',
                'kind' => $i % 3 === 0 ? 'dsse' : 'hashedrekord',
                'spec' => ['digest' => base64_encode(hash('sha256', (string) $i, true))],
            ], JSON_THROW_ON_ERROR);
        }

        return new self($bodies);
    }

    public function checkpoint(): string
    {
        return $this->files['/api/v2/checkpoint'];
    }

    /** Overwrite what the log serves at a path (a tampered or missing tile). */
    public function set(string $path, ?string $bytes): void
    {
        if ($bytes === null) {
            unset($this->files[$path]);
        } else {
            $this->files[$path] = $bytes;
        }
    }

    /** @return list<string> */
    public function paths(): array
    {
        return array_keys($this->files);
    }

    public function respond(RequestInterface $request): ResponseInterface
    {
        $factory = new Psr17Factory;
        $path = $request->getUri()->getPath();

        if (! isset($this->files[$path])) {
            return $factory->createResponse(404)->withBody($factory->createStream('no such object'));
        }

        return $factory->createResponse(200)->withBody($factory->createStream($this->files[$path]));
    }

    private function build(): void
    {
        $hashes = array_map(Merkle::leafHash(...), $this->bodies);

        foreach (array_chunk($this->bodies, 256) as $index => $chunk) {
            $bundle = '';

            foreach ($chunk as $body) {
                $bundle .= pack('n', strlen($body)) . $body;
            }
            $this->files[TilePath::entries($index, count($chunk) === 256 ? null : count($chunk))] = $bundle;
        }

        for ($level = 0; $hashes !== []; $level++) {
            foreach (array_chunk($hashes, 256) as $index => $chunk) {
                $this->files[TilePath::tile($level, $index, count($chunk) === 256 ? null : count($chunk))] = implode('', $chunk);
            }
            $next = [];

            for ($i = 0; $i + 256 <= count($hashes); $i += 256) {
                $next[] = self::mth(array_slice($hashes, $i, 256));
            }
            $hashes = $next;
        }
        $text = self::ORIGIN . "\n" . count($this->bodies) . "\n" . base64_encode($this->rootHash) . "\n";
        $this->files['/api/v2/checkpoint'] = (string) $this->signer->sign($text);
    }

    /**
     * MTH over leaf (or subtree) hashes, RFC 6962 Section 2.1.
     *
     * @param list<string> $hashes
     */
    private static function mth(array $hashes): string
    {
        if (count($hashes) === 1) {
            return $hashes[0];
        }
        $k = Merkle::split(count($hashes));

        return Merkle::nodeHash(self::mth(array_slice($hashes, 0, $k)), self::mth(array_slice($hashes, $k)));
    }
}
