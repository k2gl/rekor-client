<?php

declare(strict_types=1);

/*
 * Records a slice of the public Rekor v2 log for the test suite: the checkpoint,
 * the entry bundle of the head tile and every hash tile a proof for its last
 * entry touches. It waits for a moment when the head tile is small, so the
 * bundle stays under a hundred kilobytes.
 *
 *   php tests/fixtures/rekor-v2/record.php
 *
 * The log's key is read from Sigstore's trusted root (root-signing on GitHub).
 */

use K2gl\RekorClient\LogReader;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

require __DIR__ . '/../../../vendor/autoload.php';

$origin = 'log2025-1.rekor.sigstore.dev';
$baseUrl = 'https://' . $origin;
$dir = __DIR__;

$trustedRoot = json_decode((string) file_get_contents('https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json'), true, flags: JSON_THROW_ON_ERROR);
$publicKeyDer = null;

foreach ($trustedRoot['tlogs'] as $tlog) {
    if ($tlog['baseUrl'] === $baseUrl) {
        $publicKeyDer = base64_decode($tlog['publicKey']['rawBytes'], true);
    }
}

if (! is_string($publicKeyDer)) {
    fwrite(STDERR, "The trusted root lists no {$baseUrl}\n");
    exit(1);
}

$recorder = new class ($baseUrl) implements ClientInterface {
    /** @var array<string, string> */
    public array $files = [];

    public function __construct(private readonly string $baseUrl) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $path = $request->getUri()->getPath();
        $curl = curl_init($this->baseUrl . $path);
        curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true]);
        $body = (string) curl_exec($curl);
        $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);

        if ($status === 200) {
            $this->files[$path] = $body;
        }
        $factory = new Psr17Factory;

        return $factory->createResponse($status)->withBody($factory->createStream($body));
    }
};

$reader = new LogReader($recorder, new Psr17Factory, $baseUrl, $origin, $publicKeyDer, retries: 0);

// Wait for a small head tile: the log adds an entry every second or so.
for ($attempt = 0; ; $attempt++) {
    $checkpoint = $reader->checkpoint();
    $width = $checkpoint->treeSize % 256;

    if ($width >= 1 && $width <= 40) {
        break;
    }

    if ($attempt >= 60) {
        fwrite(STDERR, "The head tile did not get small enough in time (width {$width}).\n");
        exit(1);
    }
    fwrite(STDERR, "tree size {$checkpoint->treeSize}, head tile {$width} wide; waiting…\n");
    sleep(5);
}

$recorder->files = [];
$logIndex = $checkpoint->treeSize - 1;
$entry = $reader->entry($logIndex);

$manifest = ['origin' => $origin, 'publicKeyDer' => base64_encode($publicKeyDer), 'logIndex' => $logIndex, 'files' => []];

foreach (glob($dir . '/*.bin') ?: [] as $stale) {
    unlink($stale);
}

foreach ($recorder->files as $path => $bytes) {
    $name = str_replace(['/api/v2/', '/'], ['', '_'], $path) . '.bin';
    file_put_contents($dir . '/' . $name, $bytes);
    $manifest['files'][$path] = $name;
}
file_put_contents($dir . '/manifest.json', json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

printf("Recorded entry %d of a %d-entry tree: %d files, %d bytes.\n", $logIndex, $entry->inclusionProof?->treeSize ?? 0, count($recorder->files), array_sum(array_map('strlen', $recorder->files)));
