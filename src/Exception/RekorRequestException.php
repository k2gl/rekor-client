<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Exception;

use RuntimeException;

/** The request never produced a usable HTTP response (transport error, or the request could not be built). */
final class RekorRequestException extends RuntimeException implements RekorClientException {}
