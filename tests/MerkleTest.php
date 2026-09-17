<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Tests;

use K2gl\RekorClient\Exception\InvalidArgumentException;
use K2gl\RekorClient\Internal\Merkle;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * The Certificate Transparency test tree: eight leaves whose roots at every
 * size are published with the reference implementations (RFC 6962 hashing).
 */
#[CoversClass(Merkle::class)]
final class MerkleTest extends TestCase
{
    private const LEAVES = ['', "\x00", "\x10", "\x20\x21", "\x30\x31", "\x40\x41\x42\x43", "\x50\x51\x52\x53\x54\x55\x56\x57", "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"];

    private const ROOTS = [
        1 => '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
        2 => 'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
        3 => 'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
        4 => 'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
        5 => '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
        6 => '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
        7 => 'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
        8 => '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
    ];

    public function testEveryInclusionPathLeadsToThePublishedRoot(): void
    {
        foreach (self::ROOTS as $treeSize => $root) {
            for ($index = 0; $index < $treeSize; $index++) {
                $path = Merkle::inclusionPath($index, $treeSize, self::subtreeHash(...));

                $reached = Merkle::rootFromPath(Merkle::leafHash(self::LEAVES[$index]), $index, $treeSize, $path);

                fact($reached === null ? null : bin2hex($reached))->is($root);
            }
        }
    }

    public function testAPathOfTheWrongShapeLeadsNowhere(): void
    {
        $path = Merkle::inclusionPath(2, 5, self::subtreeHash(...));
        $leaf = Merkle::leafHash(self::LEAVES[2]);

        fact(Merkle::rootFromPath($leaf, 2, 5, array_slice($path, 1)))->null();
        fact(Merkle::rootFromPath($leaf, 2, 5, [...$path, $leaf]))->null();
        fact(Merkle::rootFromPath($leaf, 5, 5, $path))->null();
    }

    public function testASingleLeafTreeIsItsOwnRoot(): void
    {
        fact(Merkle::inclusionPath(0, 1, self::subtreeHash(...)))->is([]);
        fact(bin2hex((string) Merkle::rootFromPath(Merkle::leafHash(''), 0, 1, [])))->is(self::ROOTS[1]);
    }

    public function testSplitsAtTheLargestPowerOfTwoBelowTheSize(): void
    {
        fact(Merkle::split(2))->is(1);
        fact(Merkle::split(3))->is(2);
        fact(Merkle::split(256))->is(128);
        fact(Merkle::split(257))->is(256);
        fact(static fn () => Merkle::split(1))->throws(InvalidArgumentException::class);
    }

    public function testRejectsALeafOutsideTheTree(): void
    {
        fact(static fn () => Merkle::inclusionPath(8, 8, self::subtreeHash(...)))->throws(InvalidArgumentException::class);
    }

    /** MTH(D[start:end]) by plain recursion over the test leaves. */
    private static function subtreeHash(int $start, int $end): string
    {
        if ($end - $start === 1) {
            return Merkle::leafHash(self::LEAVES[$start]);
        }
        $k = Merkle::split($end - $start);

        return Merkle::nodeHash(self::subtreeHash($start, $start + $k), self::subtreeHash($start + $k, $end));
    }
}
