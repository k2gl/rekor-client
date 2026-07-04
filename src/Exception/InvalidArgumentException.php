<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Exception;

use InvalidArgumentException as BaseInvalidArgumentException;

/** Thrown when an argument handed to the client or a request type is malformed. */
final class InvalidArgumentException extends BaseInvalidArgumentException implements RekorClientException {}
