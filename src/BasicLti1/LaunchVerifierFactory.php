<?php

namespace BasicLti1;

use Oauth1\RequestVerifierFactory;
use Oauth1\SignatureMethod;
use Psr\SimpleCache\CacheInterface;

/**
 * Assembles a LaunchVerifier wired to HMAC-SHA1 - see LaunchRequestBuilderFactory for why that
 * is the only signature method Basic LTI allows - from a per-call nonce cache, so a caller
 * verifying launches never reaches for `new` on LaunchVerifier, RequestVerifier, or NonceStore
 * itself.
 */
final class LaunchVerifierFactory {

	public function __construct(
		private readonly RequestVerifierFactory $verifierFactory = new RequestVerifierFactory,
	) {
	}

	public function make( CacheInterface $nonceCache, string $cacheKeySuffix = '', int $timestampToleranceSeconds = 300 ): LaunchVerifier {
		return new LaunchVerifier(
			$this->verifierFactory->forMethod(SignatureMethod::HmacSha1, $nonceCache, $cacheKeySuffix, $timestampToleranceSeconds),
		);
	}

}
