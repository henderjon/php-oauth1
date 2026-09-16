<?php

namespace Oauth1;

use Psr\SimpleCache\CacheInterface;

/**
 * Tracks which nonces RequestVerifier has already accepted, so a replayed request - the same
 * nonce/timestamp/consumer-key/token combination sent twice - is rejected the second time (RFC
 * 5849 §3.3).
 *
 * Backed by an injected PSR-16 cache, the same way Oidc's AuthorizationStateStore is - and
 * inherits the same caveat: a mock-mode cache that silently no-ops writes would make every nonce
 * look unused, so this is not a defense a caller can rely on against a cache configured that
 * way. claim() is a get-then-set, not an atomic add - PSR-16 has no portable atomic primitive -
 * so a genuine race between two requests with the same nonce arriving at the same instant could
 * both be accepted; this is an accepted, documented gap, not a bug to chase.
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
	 */
	public function claim( string $consumerKey, string $token, string $nonce, string $timestamp, int $ttlSeconds ): bool {
		$key = 'oauth1_nonce_' . hash('sha256', "{$consumerKey}\0{$token}\0{$nonce}\0{$timestamp}") . $this->cacheKeySuffix;

		if ( $this->cache->has($key) ) {
			return false;
		}

		$this->cache->set($key, true, $ttlSeconds);

		return true;
	}

}
