<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Internal;

use Closure;
use K2gl\RekorClient\Exception\InvalidArgumentException;
use K2gl\RekorClient\Exception\RekorResponseException;

/**
 * Subtree hashes of a tiled log at one tree size. A level-L tile holds the
 * hashes of consecutive 256^L-leaf subtrees, so an aligned range of that size
 * is read straight from a tile and anything else is hashed from smaller ranges
 * (RFC 6962). Tiles and computed ranges are kept for the life of the tree, i.e.
 * one checkpoint, so the proofs of neighbouring entries share their fetches.
 *
 * @internal
 */
final class TileTree
{
    public const WIDTH = 256;

    private const HASH_BYTES = 32;

    /** 256^8 does not fit an int; no log comes near it. */
    private const MAX_LEVEL = 7;

    /** @var array<string, string> */
    private array $tiles = [];

    /** @var array<string, string> */
    private array $ranges = [];

    /**
     * @param Closure(int, int, ?int): string $fetch tile bytes for (level, index, width or null when full)
     */
    public function __construct(
        private readonly int $treeSize,
        private readonly Closure $fetch,
    ) {}

    /** MTH(D[start:end]). */
    public function hash(int $start, int $end): string
    {
        if ($start < 0 || $end > $this->treeSize || $start >= $end) {
            throw new InvalidArgumentException('The subtree range must lie inside the tree.');
        }
        $size = $end - $start;

        if ($size === 1) {
            return $this->node(0, $start);
        }
        $span = self::WIDTH;
        $level = 1;

        while ($span <= $size) {
            if ($span === $size && $start % $span === 0) {
                return $this->node($level, intdiv($start, $span));
            }

            if ($level === self::MAX_LEVEL) {
                break;
            }
            $span *= self::WIDTH;
            $level++;
        }
        $key = $start . ':' . $end;

        if (isset($this->ranges[$key])) {
            return $this->ranges[$key];
        }
        $k = Merkle::split($size);

        return $this->ranges[$key] = Merkle::nodeHash($this->hash($start, $start + $k), $this->hash($start + $k, $end));
    }

    /** The width of tile $index at $level for this tree size: 256, or fewer at the head. */
    public function width(int $level, int $index): int
    {
        $nodes = intdiv($this->treeSize, self::WIDTH ** $level);
        $first = $index * self::WIDTH;

        if ($first >= $nodes) {
            throw new InvalidArgumentException(sprintf('Tile %d/%d lies beyond a tree of %d entries.', $level, $index, $this->treeSize));
        }

        return min(self::WIDTH, $nodes - $first);
    }

    /** Hash number $index at tile level $level. */
    private function node(int $level, int $index): string
    {
        $tile = $this->tile($level, intdiv($index, self::WIDTH));
        $offset = ($index % self::WIDTH) * self::HASH_BYTES;

        if (strlen($tile) < $offset + self::HASH_BYTES) {
            throw new RekorResponseException(sprintf('Tile %d/%d is shorter than the tree size implies.', $level, intdiv($index, self::WIDTH)));
        }

        return substr($tile, $offset, self::HASH_BYTES);
    }

    private function tile(int $level, int $index): string
    {
        $key = $level . '/' . $index;

        if (isset($this->tiles[$key])) {
            return $this->tiles[$key];
        }
        $width = $this->width($level, $index);
        $bytes = ($this->fetch)($level, $index, $width === self::WIDTH ? null : $width);

        if (strlen($bytes) !== $width * self::HASH_BYTES) {
            throw new RekorResponseException(sprintf(
                'Tile %d/%d is %d bytes; a tile %d hashes wide is %d.',
                $level,
                $index,
                strlen($bytes),
                $width,
                $width * self::HASH_BYTES,
            ));
        }

        return $this->tiles[$key] = $bytes;
    }
}
