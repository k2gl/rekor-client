<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Exception;

use RuntimeException;

/** Rekor answered, but with an error status or a body this client cannot make sense of. */
final class RekorResponseException extends RuntimeException implements RekorClientException
{
    public function __construct(string $message, public readonly ?int $statusCode = null)
    {
        parent::__construct($message);
    }
}
