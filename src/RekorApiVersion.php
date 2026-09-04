<?php

declare(strict_types=1);

namespace K2gl\RekorClient;

/**
 * Which major version of the Rekor API a log speaks. The case values are the
 * `majorApiVersion` Sigstore publishes per log in the signing config, so a
 * client can be built straight from that entry:
 * `RekorApiVersion::from($log['majorApiVersion'])`.
 *
 * Sigstore's default signing config still lists only rekor.sigstore.dev at
 * major version 1; the v2 logs live in a separate, opt-in signing config. Point
 * a client at the log the config gave you, and tell it the version from the
 * same place rather than assuming.
 */
enum RekorApiVersion: int
{
    /** The original REST log (rekor.sigstore.dev): hashedrekord 0.0.1, entries carry an integrated time and a SET. */
    case V1 = 1;

    /** The tile-backed log (rekor-tiles): hashedrekord 0.0.2, no per-entry time — a timestamp needs a TSA. */
    case V2 = 2;
}
