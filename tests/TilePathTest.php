<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Tests;

use K2gl\RekorClient\Exception\InvalidArgumentException;
use K2gl\RekorClient\Internal\TilePath;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(TilePath::class)]
final class TilePathTest extends TestCase
{
    #[TestWith([0, '000'])]
    #[TestWith([6, '006'])]
    #[TestWith([999, '999'])]
    #[TestWith([1000, 'x001/000'])]
    #[TestWith([1740, 'x001/740'])]
    #[TestWith([445621, 'x445/621'])]
    #[TestWith([1234067, 'x001/x234/067'])]
    public function testWritesTheIndexInThreeDigitGroups(int $index, string $expected): void
    {
        fact(TilePath::index($index))->is($expected);
    }

    public function testBuildsTileAndEntryPaths(): void
    {
        fact(TilePath::tile(0, 445621, null))->is('/api/v2/tile/0/x445/621');
        fact(TilePath::tile(1, 1740, 181))->is('/api/v2/tile/1/x001/740.p/181');
        fact(TilePath::entries(0, null))->is('/api/v2/tile/entries/000');
        fact(TilePath::entries(445621, 58))->is('/api/v2/tile/entries/x445/621.p/58');
    }

    #[TestWith([0])]
    #[TestWith([256])]
    public function testRejectsAPartialWidthOutsideOneToTwoFiftyFive(int $width): void
    {
        fact(static fn () => TilePath::tile(0, 1, $width))->throws(InvalidArgumentException::class);
    }

    public function testRejectsNegativeIndexAndLevel(): void
    {
        fact(static fn () => TilePath::index(-1))->throws(InvalidArgumentException::class);
        fact(static fn () => TilePath::tile(-1, 0, null))->throws(InvalidArgumentException::class);
    }
}
