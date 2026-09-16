<?php

namespace BasicLti1;

use Oauth1\CurrentClock;
use Oauth1\RequestVerifierFactory;
use Oauth1\SignatureMethod;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * Assembles a LaunchVerifier wired to HMAC-SHA1 - see LaunchRequestBuilderFactory for why that
 * is the only signature method Basic LTI allows - from a per-call nonce cache, so a caller
 * verifying launches never reaches for `new` on LaunchVerifier, RequestVerifier, or NonceStore
 * itself.
 *
 * Takes the same raw collaborators (clock, logger) Oauth1\RequestVerifierFactory does, rather
 * than a pre-built RequestVerifierFactory, and builds one internally - see
 * LaunchRequestBuilderFactory's docblock for why, on the signing side, that same reasoning
 * applies here too.
 */
final class LaunchVerifierFactory {

	public function __construct(
		private readonly ClockInterface $clock = new CurrentClock,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	public function make( CacheInterface $nonceCache, string $cacheKeySuffix = '', int $timestampToleranceSeconds = 300 ): LaunchVerifier {
		$verifier = (new RequestVerifierFactory($this->clock, $this->logger))
			->forMethod(SignatureMethod::HmacSha1, $nonceCache, $cacheKeySuffix, $timestampToleranceSeconds);

		return new LaunchVerifier($verifier, $this->logger);
	}

}
