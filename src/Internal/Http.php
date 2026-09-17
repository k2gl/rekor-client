<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Internal;

use Closure;
use JsonException;
use K2gl\RekorClient\Exception\RekorRequestException;
use LogicException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * The HTTP layer the write and the read path share: requests against the
 * log's base URL, sent again while the log answers with something worth
 * another go — a transport failure, or one of the statuses a log uses to say
 * "busy, come back". A 409 is handed back rather than retried; what it means
 * differs per version.
 *
 * @internal
 */
final class Http
{
    /** Extra attempts after the first one. */
    public const DEFAULT_RETRIES = 2;

    /** Doubles per attempt, so 0.2s, 0.4s, 0.8s … before a cap. */
    private const BACKOFF_MICROSECONDS = 200_000;

    private const MAX_BACKOFF_MICROSECONDS = 5_000_000;

    /** A log asking to be left alone for longer than this is not worth waiting for. */
    private const MAX_RETRY_AFTER_SECONDS = 30;

    /**
     * Statuses worth trying again. A duplicate (409) is deliberately absent: the
     * entry is already in the log, so a retry would only produce it again.
     */
    private const RETRYABLE_STATUSES = [408, 429, 499, 500, 502, 503, 504];

    private readonly string $baseUrl;

    /** @var Closure(int): mixed */
    private readonly Closure $sleeper;

    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        string $baseUrl,
        private readonly ?StreamFactoryInterface $streamFactory = null,
        private readonly int $retries = self::DEFAULT_RETRIES,
        ?Closure $sleeper = null,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->sleeper = $sleeper ?? usleep(...);
    }

    public function get(string $path, string $accept = 'application/json'): ResponseInterface
    {
        return $this->send(
            $this->requestFactory->createRequest('GET', $this->baseUrl . $path)->withHeader('Accept', $accept),
        );
    }

    /** @param array<string, mixed> $body */
    public function postJson(string $path, array $body): ResponseInterface
    {
        if ($this->streamFactory === null) {
            throw new LogicException('A stream factory is needed to send a request body.');
        }

        try {
            $json = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new RekorRequestException('Could not encode the Rekor request body: ' . $e->getMessage(), previous: $e);
        }

        return $this->send(
            $this->requestFactory->createRequest('POST', $this->baseUrl . $path)
                ->withHeader('Accept', 'application/json')
                ->withHeader('Content-Type', 'application/json')
                ->withBody($this->streamFactory->createStream($json)),
        );
    }

    private function send(RequestInterface $request): ResponseInterface
    {
        $attempts = max(1, $this->retries + 1);

        for ($attempt = 1; ; $attempt++) {
            try {
                $response = $this->httpClient->sendRequest($request);
            } catch (ClientExceptionInterface $e) {
                if ($attempt >= $attempts) {
                    throw new RekorRequestException('Rekor request failed: ' . $e->getMessage(), previous: $e);
                }
                $this->pause($attempt, null);

                continue;
            }

            if ($attempt >= $attempts || ! in_array($response->getStatusCode(), self::RETRYABLE_STATUSES, true)) {
                return $response;
            }
            $this->pause($attempt, $response);
        }
    }

    /** Wait before the next attempt: as long as the log asked, else backing off. */
    private function pause(int $attempt, ?ResponseInterface $response): void
    {
        $asked = $response === null ? null : self::retryAfterSeconds($response);

        if ($asked !== null) {
            ($this->sleeper)($asked * 1_000_000);

            return;
        }
        $backoff = min(self::BACKOFF_MICROSECONDS << ($attempt - 1), self::MAX_BACKOFF_MICROSECONDS);

        // Jitter, so several signers retrying at once do not march in step.
        ($this->sleeper)($backoff + random_int(0, intdiv($backoff, 2)));
    }

    /** The Retry-After delay in seconds, when the log sent a usable one. */
    private static function retryAfterSeconds(ResponseInterface $response): ?int
    {
        $header = trim($response->getHeaderLine('Retry-After'));

        if ($header === '' || preg_match('/^\d+$/', $header) !== 1) {
            return null;
        }
        $seconds = (int) $header;

        return $seconds >= 0 && $seconds <= self::MAX_RETRY_AFTER_SECONDS ? $seconds : null;
    }
}
