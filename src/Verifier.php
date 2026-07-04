<?php

declare(strict_types=1);

namespace K2gl\RekorClient;

use K2gl\RekorClient\Exception\InvalidArgumentException;

/**
 * The verifier a hashedrekord entry is bound to: either a bare public key or a
 * Fulcio (keyless) certificate, tagged with the signing algorithm. Exactly the
 * `Verifier` message Rekor v2 expects inside a submission.
 */
final class Verifier
{
    private const KIND_PUBLIC_KEY = 'publicKey';
    private const KIND_CERTIFICATE = 'x509Certificate';

    /**
     * @param self::KIND_* $kind
     * @param string       $rawBytes DER-encoded key or certificate
     */
    private function __construct(
        private readonly string $kind,
        private readonly string $rawBytes,
        private readonly KeyDetails $keyDetails,
    ) {
        if ($rawBytes === '') {
            throw new InvalidArgumentException('Verifier raw bytes must not be empty.');
        }
    }

    /** A bare public key (raw DER SubjectPublicKeyInfo). */
    public static function publicKey(string $der, KeyDetails $keyDetails): self
    {
        return new self(self::KIND_PUBLIC_KEY, $der, $keyDetails);
    }

    /** A Fulcio (or other X.509) signing certificate (raw DER) — the keyless case. */
    public static function certificate(string $der, KeyDetails $keyDetails): self
    {
        return new self(self::KIND_CERTIFICATE, $der, $keyDetails);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            $this->kind => ['rawBytes' => base64_encode($this->rawBytes)],
            'keyDetails' => $this->keyDetails->value,
        ];
    }
}
