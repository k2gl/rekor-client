<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Internal;

use K2gl\RekorClient\Exception\InvalidArgumentException;

/**
 * The read-path URLs of a tiled log (C2SP tlog-tiles, as Rekor v2 serves them
 * under /api/v2). A tile index is written in three-digit groups, every group
 * but the last prefixed with "x": 1234067 is `x001/x234/067`, 6 is `006`. A
 * partial tile — the head of the tree, not yet 256 hashes wide — gets a `.p/W`
 * suffix naming its width.
 *
 * @internal
 *
 * @see https://c2sp.org/tlog-tiles
 */
final class TilePath
{
    public static function index(int $index): string
    {
        if ($index < 0) {
            throw new InvalidArgumentException('A tile index must not be negative.');
        }
        $path = sprintf('%03d', $index % 1000);
        $index = intdiv($index, 1000);

        while ($index > 0) {
            $path = sprintf('x%03d/', $index % 1000) . $path;
            $index = intdiv($index, 1000);
        }

        return $path;
    }

    /** A hash tile; `$width` is null for a full tile. */
    public static function tile(int $level, int $index, ?int $width): string
    {
        if ($level < 0) {
            throw new InvalidArgumentException('A tile level must not be negative.');
        }

        return '/api/v2/tile/' . $level . '/' . self::index($index) . self::partial($width);
    }

    /** An entry bundle: the entries whose hashes a level-0 tile holds. */
    public static function entries(int $index, ?int $width): string
    {
        return '/api/v2/tile/entries/' . self::index($index) . self::partial($width);
    }

    private static function partial(?int $width): string
    {
        if ($width === null) {
            return '';
        }

        if ($width < 1 || $width > 255) {
            throw new InvalidArgumentException('A partial tile is 1 to 255 hashes wide.');
        }

        return '.p/' . $width;
    }
}
