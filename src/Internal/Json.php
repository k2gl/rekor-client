<?php

declare(strict_types=1);

namespace K2gl\RekorClient\Internal;

use K2gl\RekorClient\Exception\RekorResponseException;

/**
 * Small typed readers over Rekor's JSON, so parsing a response is total: every
 * missing or wrong-typed field fails as a {@see RekorResponseException} rather
 * than a stray PHP warning. Rekor encodes 64-bit integers as JSON strings, which
 * {@see self::intString()} converts back.
 *
 * @internal
 */
final class Json
{
    /** @param array<string, mixed> $data */
    public static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value)) {
            throw new RekorResponseException(sprintf('Expected string at "%s" in the Rekor response.', $key));
        }

        return $value;
    }

    /**
     * @param  array<string, mixed> $data
     * @return array<string, mixed>
     */
    public static function object(array $data, string $key): array
    {
        $value = $data[$key] ?? null;

        if (! is_array($value)) {
            throw new RekorResponseException(sprintf('Expected object at "%s" in the Rekor response.', $key));
        }

        /** @var array<string, mixed> $value */
        return $value;
    }

    /** @param array<string, mixed> $data */
    public static function base64(array $data, string $key): string
    {
        $decoded = base64_decode(self::string($data, $key), true);

        if ($decoded === false) {
            throw new RekorResponseException(sprintf('Field "%s" in the Rekor response is not valid base64.', $key));
        }

        return $decoded;
    }

    /** @param array<string, mixed> $data */
    public static function intString(array $data, string $key): int
    {
        $value = $data[$key] ?? null;

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && $value !== '' && ctype_digit(ltrim($value, '-')) && $value === (string) (int) $value) {
            return (int) $value;
        }

        throw new RekorResponseException(sprintf('Expected an integer at "%s" in the Rekor response.', $key));
    }

    /**
     * @param  array<string, mixed> $data
     * @return list<string>
     */
    public static function base64List(array $data, string $key): array
    {
        $value = $data[$key] ?? null;

        if (! is_array($value) || ! array_is_list($value)) {
            throw new RekorResponseException(sprintf('Expected an array at "%s" in the Rekor response.', $key));
        }
        $out = [];

        foreach ($value as $item) {
            if (! is_string($item)) {
                throw new RekorResponseException(sprintf('Expected base64 strings at "%s" in the Rekor response.', $key));
            }
            $decoded = base64_decode($item, true);

            if ($decoded === false) {
                throw new RekorResponseException(sprintf('An entry in "%s" is not valid base64.', $key));
            }
            $out[] = $decoded;
        }

        return $out;
    }

    /**
     * A lower-case hex string decoded to raw bytes. Rekor v1 hex-encodes what v2
     * base64-encodes: log ids, root hashes and proof hashes.
     *
     * @param array<string, mixed> $data
     */
    public static function hex(array $data, string $key): string
    {
        $decoded = self::decodeHex(self::string($data, $key));

        if ($decoded === null) {
            throw new RekorResponseException(sprintf('Field "%s" in the Rekor response is not valid hex.', $key));
        }

        return $decoded;
    }

    /**
     * @param  array<string, mixed> $data
     * @return list<string>
     */
    public static function hexList(array $data, string $key): array
    {
        $value = $data[$key] ?? null;

        if (! is_array($value) || ! array_is_list($value)) {
            throw new RekorResponseException(sprintf('Expected an array at "%s" in the Rekor response.', $key));
        }
        $out = [];

        foreach ($value as $item) {
            $decoded = is_string($item) ? self::decodeHex($item) : null;

            if ($decoded === null) {
                throw new RekorResponseException(sprintf('An entry in "%s" is not valid hex.', $key));
            }
            $out[] = $decoded;
        }

        return $out;
    }

    private static function decodeHex(string $value): ?string
    {
        if ($value === '' || strlen($value) % 2 !== 0 || ! ctype_xdigit($value)) {
            return null;
        }
        $decoded = hex2bin($value);

        return $decoded === false ? null : $decoded;
    }
}
