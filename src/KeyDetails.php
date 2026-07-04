<?php

declare(strict_types=1);

namespace K2gl\RekorClient;

/**
 * The signing-key algorithms Rekor names on a verifier, spelled exactly as the
 * Sigstore protobuf JSON mapping expects (`PublicKeyDetails`).
 *
 * @see https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_common.proto
 */
enum KeyDetails: string
{
    case PKIX_ECDSA_P256_SHA_256 = 'PKIX_ECDSA_P256_SHA_256';
    case PKIX_ECDSA_P384_SHA_384 = 'PKIX_ECDSA_P384_SHA_384';
    case PKIX_ECDSA_P521_SHA_512 = 'PKIX_ECDSA_P521_SHA_512';
    case PKIX_RSA_PKCS1V15_2048_SHA256 = 'PKIX_RSA_PKCS1V15_2048_SHA256';
    case PKIX_RSA_PKCS1V15_3072_SHA256 = 'PKIX_RSA_PKCS1V15_3072_SHA256';
    case PKIX_RSA_PKCS1V15_4096_SHA256 = 'PKIX_RSA_PKCS1V15_4096_SHA256';
    case PKIX_ED25519 = 'PKIX_ED25519';
}
