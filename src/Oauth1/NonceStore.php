<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Psr\SimpleCache\CacheInterface;

/**
 * Tracks which nonces RequestVerifier has already accepted, so a replayed request - the same
 * nonce/timestamp/consumer-key/token combination sent twice - is rejected the second time (RFC
 * 5849 §3.3).
 *
 * Backed by an injected PSR-16 cache, the same way Oidc's AuthorizationStateStore is - and
 * inherits the same caveat: a mock-mode cache that silently no-ops writes but still reports
 * success would make every nonce look unused, so this is not a defense a caller can rely on
 * against a cache configured that way. claim() is a get-then-set, not an atomic add - PSR-16 has
 * no portable atomic primitive - so a genuine race between two requests with the same nonce
 * arriving at the same instant could both be accepted; this is an accepted, documented gap, not
 * a bug to chase.
 *
 * A cache that *honestly reports* a write failure is a different case entirely, and is not
 * silently treated the same as a successful claim - see claim()'s own docblock.
 */
final class NonceStore {

	public function __construct(
		private readonly CacheInterface $cache,
		private readonly string $cacheKeySuffix = '',
	) {
	}

	/**
	 * Returns true the first time a given key is claimed, false on every repeat - the caller's
	 * signal to reject the request as a replay.
	 *
	 * @throws SigningException if the underlying cache reports that it could not persist the
	 *                           claim, or if the cache itself throws while being asked
	 *                           (`\Psr\SimpleCache\InvalidArgumentException`, a client-specific
	 *                           connection failure). Deliberately not the same `false` a replay
	 *                           returns - a persistence failure is an infrastructure problem, not
	 *                           tampering, and RequestVerifier logs/reports the two differently.
	 *                           Collapsing them would mean a cache outage gets logged as
	 *                           `security_relevant: true` tampering purely because the code that
	 *                           reports it cannot tell the two apart. Wrapped rather than left to
	 *                           propagate raw, per this library's own rule for external calls.
	 */
	public function claim( string $consumerKey, string $token, string $nonce, string $timestamp, int $ttlSeconds ): bool {
		$key = 'oauth1_nonce_' . hash('sha256', "{$consumerKey}\0{$token}\0{$nonce}\0{$timestamp}") . $this->cacheKeySuffix;

		try {
			$alreadyClaimed = $this->cache->has($key);
		} catch ( \Throwable $exception ) {
			// No Credentials in scope to attach a consumer key to this exception - the same
			// reason SignatureBaseString's own exceptions carry none; RequestVerifier's caller
			// rewraps this with one, mirroring its existing baseString() catch block.
			throw new SigningException('The underlying cache threw while checking a nonce claim', previous: $exception);
		}

		if ( $alreadyClaimed ) {
			return false;
		}

		try {
			$persisted = $this->cache->set($key, true, $ttlSeconds);
		} catch ( \Throwable $exception ) {
			throw new SigningException('The underlying cache threw while persisting a nonce claim', previous: $exception);
		}

		if ( ! $persisted ) {
			throw new SigningException('Failed to persist a claimed nonce - the cache write did not succeed');
		}

		return true;
	}

}
