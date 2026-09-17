<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Internal;

use K2gl\RekorClient\Exception\RekorResponseException;

/**
 * An entry bundle: the log entries behind one level-0 tile, each prefixed with
 * its length as a big-endian uint16 (C2SP tlog-tiles). Rekor v2 stores the
 * canonical JSON of the entry as the entry itself.
 *
 * @internal
 */
final class EntryBundle
{
    /** @return list<string> */
    public static function parse(string $bytes): array
    {
        $entries = [];
        $offset = 0;
        $length = strlen($bytes);

        while ($offset < $length) {
            if ($offset + 2 > $length) {
                throw new RekorResponseException('The entry bundle ends in the middle of a length prefix.');
            }
            $size = (ord($bytes[$offset]) << 8) | ord($bytes[$offset + 1]);
            $offset += 2;

            if ($offset + $size > $length) {
                throw new RekorResponseException('The entry bundle ends in the middle of an entry.');
            }
            $entries[] = substr($bytes, $offset, $size);
            $offset += $size;
        }

        return $entries;
    }
}
