<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Internal;

use Closure;
use K2gl\RekorClient\Exception\InvalidArgumentException;

/**
 * The RFC 6962 Merkle tree: leaf and node hashes, the split point of a tree,
 * an inclusion path built from subtree hashes, and the root such a path leads
 * to (RFC 9162 Section 2.1.3.2).
 *
 * @internal
 *
 * @see https://www.rfc-editor.org/rfc/rfc6962#section-2.1
 */
final class Merkle
{
    public static function leafHash(string $entry): string
    {
        return hash('sha256', "\x00" . $entry, true);
    }

    public static function nodeHash(string $left, string $right): string
    {
        return hash('sha256', "\x01" . $left . $right, true);
    }

    /** The largest power of two smaller than $n (n >= 2): where a tree of n leaves splits. */
    public static function split(int $n): int
    {
        if ($n < 2) {
            throw new InvalidArgumentException('Only a tree of two leaves or more splits.');
        }
        $k = 1;

        while ($k * 2 < $n) {
            $k *= 2;
        }

        return $k;
    }

    /**
     * PATH(m, D[n]) of RFC 6962 Section 2.1.1: the sibling hashes that lead from
     * leaf m to the root of a tree of n leaves, leaf end first. Each sibling is a
     * subtree hash MTH(D[start:end]) the callback supplies.
     *
     * @param  Closure(int, int): string $subtreeHash
     * @return list<string>
     */
    public static function inclusionPath(int $index, int $treeSize, Closure $subtreeHash): array
    {
        if ($index < 0 || $index >= $treeSize) {
            throw new InvalidArgumentException('The leaf index must be inside the tree.');
        }
        $path = [];
        $start = 0;
        $end = $treeSize;

        while ($end - $start > 1) {
            $k = self::split($end - $start);

            if ($index < $start + $k) {
                $path[] = $subtreeHash($start + $k, $end);
                $end = $start + $k;
            } else {
                $path[] = $subtreeHash($start, $start + $k);
                $start += $k;
            }
        }

        return array_reverse($path);
    }

    /**
     * The root an inclusion path leads to, or null when the path has the wrong
     * shape for that leaf and tree size.
     *
     * @param list<string> $path sibling hashes, leaf end first
     */
    public static function rootFromPath(string $leafHash, int $index, int $treeSize, array $path): ?string
    {
        if ($index < 0 || $index >= $treeSize) {
            return null;
        }
        $fn = $index;
        $sn = $treeSize - 1;
        $root = $leafHash;

        foreach ($path as $sibling) {
            if ($sn === 0) {
                return null;
            }

            if (($fn & 1) === 1 || $fn === $sn) {
                $root = self::nodeHash($sibling, $root);

                while (($fn & 1) === 0 && $fn !== 0) {
                    $fn >>= 1;
                    $sn >>= 1;
                }
            } else {
                $root = self::nodeHash($root, $sibling);
            }
            $fn >>= 1;
            $sn >>= 1;
        }

        return $sn === 0 ? $root : null;
    }
}
