<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Exception;

use Throwable;

/**
 * Marker for every exception this package throws, so callers can catch the whole
 * family with one type.
 */
interface RekorClientException extends Throwable {}
