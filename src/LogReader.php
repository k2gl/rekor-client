<?php

declare(strict_types=1);

namespace K2gl\RekorClient;

use Closure;
use K2gl\RekorClient\Exception\InvalidArgumentException;
use K2gl\RekorClient\Exception\RekorResponseException;
use K2gl\RekorClient\Internal\EntryBundle;
use K2gl\RekorClient\Internal\Http;
use K2gl\RekorClient\Internal\Json;
use K2gl\RekorClient\Internal\Merkle;
use K2gl\RekorClient\Internal\TilePath;
use K2gl\RekorClient\Internal\TileTree;
use K2gl\SignedNote\Checkpoint;
use K2gl\SignedNote\Exception\InvalidNoteException;
use K2gl\SignedNote\Exception\SignatureVerificationFailed;
use K2gl\SignedNote\NoteVerifier;
use K2gl\SignedNote\VerifierKey;
use K2gl\SigstoreBundle\InclusionProof;
use K2gl\SigstoreBundle\TransparencyLogEntry;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Throwable;

/**
 * Reads a Rekor v2 (rekor-tiles) log through its C2SP tlog-tiles API: the
 * signed checkpoint, and any entry with an inclusion proof computed from the
 * hash tiles — the {@see TransparencyLogEntry} a bundle carries, built from
 * the log itself rather than from a submission response. That closes the
 * gap a duplicate submission leaves: v2 answers it with the entry's index
 * only, and this is how the entry at that index is fetched.
 *
 * Every read starts from a checkpoint verified with the log's key, and every
 * proof is checked to reproduce that checkpoint's root before it is handed
 * out; a tile that does not fit is an error, never a best effort.
 *
 * ```php
 * $reader = new LogReader($psr18, $psr17, 'https://log2025-1.rekor.sigstore.dev',
 *     origin: 'log2025-1.rekor.sigstore.dev', publicKeyDer: $logKeyFromTrustedRoot);
 *
 * $entry = $reader->entry(114068800); // TransparencyLogEntry with an inclusion proof
 * ```
 *
 * @see https://c2sp.org/tlog-tiles
 */
final class LogReader
{
    /** DER SubjectPublicKeyInfo of an Ed25519 key: this 12-byte header and the raw key. */
    private const ED25519_SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    private readonly Http $http;

    private readonly NoteVerifier $verifier;

    private readonly string $logId;

    /**
     * @param string $origin       the log's name, as its checkpoints state it (e.g. `log2025-1.rekor.sigstore.dev`)
     * @param string $publicKeyDer the log's public key as a DER SubjectPublicKeyInfo — the bytes Sigstore's trusted root carries
     * @param int    $retries      extra attempts for a request the log answers "busy" to
     */
    public function __construct(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        string $baseUrl,
        private readonly string $origin,
        string $publicKeyDer,
        int $retries = Http::DEFAULT_RETRIES,
        ?Closure $sleeper = null,
    ) {
        if ($origin === '') {
            throw new InvalidArgumentException('The log origin must not be empty.');
        }
        $this->http = new Http($httpClient, $requestFactory, $baseUrl, retries: $retries, sleeper: $sleeper);
        [$key, $this->logId] = self::logKey($origin, $publicKeyDer);
        $this->verifier = new NoteVerifier($key);
    }

    /**
     * The log id entries are stamped with: for an Ed25519 log the note key hash
     * of origin and key (what Sigstore's trusted root lists for rekor-tiles),
     * otherwise SHA-256 of the DER key.
     */
    public function logId(): string
    {
        return $this->logId;
    }

    /** The log's current head, verified with the log's key. */
    public function checkpoint(): Checkpoint
    {
        $response = $this->http->get('/api/v2/checkpoint', 'text/plain');
        $status = $response->getStatusCode();

        if ($status < 200 || $status >= 300) {
            throw new RekorResponseException(sprintf('Rekor returned HTTP %d for the checkpoint.', $status), statusCode: $status);
        }

        try {
            $checkpoint = Checkpoint::parse((string) $response->getBody());
        } catch (InvalidNoteException $e) {
            throw new RekorResponseException('The checkpoint is malformed: ' . $e->getMessage());
        }

        if ($checkpoint->origin !== $this->origin) {
            throw new RekorResponseException(sprintf('The checkpoint is for "%s", not "%s".', $checkpoint->origin, $this->origin));
        }

        try {
            $checkpoint->verify($this->verifier);
        } catch (SignatureVerificationFailed) {
            throw new RekorResponseException('The checkpoint is not signed by the log key.');
        }

        return $checkpoint;
    }

    /**
     * The entry at a log index, with an inclusion proof against the current
     * checkpoint. Throws when the log's head does not reach the index yet.
     */
    public function entry(int $logIndex): TransparencyLogEntry
    {
        return $this->fetch($logIndex, 1, strict: true)[0];
    }

    /**
     * Up to $count consecutive entries from $from, each with an inclusion proof
     * against the same checkpoint — fewer when the log's head is reached, none
     * when $from is beyond it.
     *
     * @return list<TransparencyLogEntry>
     */
    public function entries(int $from, int $count): array
    {
        return $this->fetch($from, $count, strict: false);
    }

    /** @return list<TransparencyLogEntry> */
    private function fetch(int $from, int $count, bool $strict): array
    {
        if ($from < 0 || $count < 1) {
            throw new InvalidArgumentException('A log index must not be negative, and a count must be at least one.');
        }
        $checkpoint = $this->checkpoint();

        for ($attempt = 1; ; $attempt++) {
            if ($from >= $checkpoint->treeSize) {
                if ($strict) {
                    throw new RekorResponseException(sprintf(
                        'Log index %d is not in the log yet: the checkpoint covers %d entries.',
                        $from,
                        $checkpoint->treeSize,
                    ));
                }

                return [];
            }

            try {
                return $this->read($checkpoint, $from, min($count, $checkpoint->treeSize - $from));
            } catch (RekorResponseException $e) {
                // A partial tile that is gone means the log moved on and replaced it
                // with a wider one: take a fresh checkpoint and go once more.
                if ($attempt > 1 || $e->statusCode !== 404) {
                    throw $e;
                }
                $checkpoint = $this->checkpoint();
            }
        }
    }

    /** @return list<TransparencyLogEntry> */
    private function read(Checkpoint $checkpoint, int $from, int $count): array
    {
        $treeSize = $checkpoint->treeSize;
        $tree = new TileTree(
            $treeSize,
            fn (int $level, int $index, ?int $width): string => $this->get(TilePath::tile($level, $index, $width)),
        );
        $entries = [];
        $bundleIndex = -1;
        $bodies = [];

        for ($logIndex = $from; $logIndex < $from + $count; $logIndex++) {
            if (intdiv($logIndex, TileTree::WIDTH) !== $bundleIndex) {
                $bundleIndex = intdiv($logIndex, TileTree::WIDTH);
                $bodies = $this->bundle($bundleIndex, $tree);
            }
            $body = $bodies[$logIndex % TileTree::WIDTH];
            $hashes = Merkle::inclusionPath($logIndex, $treeSize, $tree->hash(...));

            if (Merkle::rootFromPath(Merkle::leafHash($body), $logIndex, $treeSize, $hashes) !== $checkpoint->rootHash) {
                throw new RekorResponseException(sprintf('The tiles do not reproduce the checkpoint root for entry %d.', $logIndex));
            }
            [$kind, $version] = Json::kindVersion($body);

            $entries[] = new TransparencyLogEntry(
                logIndex: $logIndex,
                logId: $this->logId,
                kind: $kind,
                version: $version,
                canonicalizedBody: $body,
                inclusionProof: new InclusionProof(
                    logIndex: $logIndex,
                    rootHash: $checkpoint->rootHash,
                    treeSize: $treeSize,
                    hashes: $hashes,
                    checkpoint: (string) $checkpoint,
                ),
            );
        }

        return $entries;
    }

    /**
     * The entries behind level-0 tile $index, as many as the tree size says.
     *
     * @return list<string>
     */
    private function bundle(int $index, TileTree $tree): array
    {
        $width = $tree->width(0, $index);
        $entries = EntryBundle::parse($this->get(TilePath::entries($index, $width === TileTree::WIDTH ? null : $width)));

        if (count($entries) !== $width) {
            throw new RekorResponseException(sprintf('Entry bundle %d holds %d entries; the tree size implies %d.', $index, count($entries), $width));
        }

        return $entries;
    }

    private function get(string $path): string
    {
        $response = $this->http->get($path, '*/*');
        $status = $response->getStatusCode();

        if ($status < 200 || $status >= 300) {
            throw new RekorResponseException(sprintf('Rekor returned HTTP %d for %s.', $status, $path), statusCode: $status);
        }

        return (string) $response->getBody();
    }

    /**
     * The log's verifier key and log id from its DER public key.
     *
     * @return array{VerifierKey, string}
     */
    private static function logKey(string $origin, string $der): array
    {
        if (strlen($der) === 44 && str_starts_with($der, self::ED25519_SPKI_PREFIX)) {
            $raw = substr($der, strlen(self::ED25519_SPKI_PREFIX));

            // rekor-tiles names its key the note way: SHA-256 over the origin and the key.
            return [VerifierKey::ed25519($origin, $raw), hash('sha256', $origin . "\n\x01" . $raw, true)];
        }

        if ($der === '') {
            throw new InvalidArgumentException('The log public key must not be empty.');
        }
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";

        try {
            $key = VerifierKey::fromPem($origin, $pem);
        } catch (Throwable $e) {
            throw new InvalidArgumentException('The log public key is not a DER SubjectPublicKeyInfo this client can load: ' . $e->getMessage());
        }

        return [$key, hash('sha256', $der, true)];
    }
}
