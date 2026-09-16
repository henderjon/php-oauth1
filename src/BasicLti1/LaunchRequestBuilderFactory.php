<?php

namespace BasicLti1;

use Oauth1\CurrentClock;
use Oauth1\NonceGeneratorInterface;
use Oauth1\RandomNonceGenerator;
use Oauth1\RequestSignerFactory;
use Oauth1\SignatureMethod;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Assembles a LaunchRequestBuilder wired to HMAC-SHA1 - the Basic LTI Implementation Guide's own
 * words: "TC and TP must support and use the HMAC-SHA1 signing method" - so a caller building
 * launches never reaches for `new` on LaunchRequestBuilder, RequestSigner, or HmacSha1Signer
 * itself, and never has an opportunity to wire up a signature method Basic LTI does not allow.
 *
 * Takes the same raw collaborators (nonce generator, clock, logger) Oauth1\RequestSignerFactory
 * does, rather than a pre-built RequestSignerFactory, and builds one internally - mirroring
 * Oidc\OpenIDConnectClientFactory's own pattern of assembling every collaborator from a shared
 * set of primitives. This is what lets one `$logger` passed here reach both the Basic LTI layer
 * (LaunchRequestBuilder's own debug/error calls) and the Oauth1 layer (RequestSigner's) without
 * asking the caller to wire the same logger into two different factories separately.
 */
final class LaunchRequestBuilderFactory {

	public function __construct(
		private readonly NonceGeneratorInterface $nonceGenerator = new RandomNonceGenerator,
		private readonly ClockInterface $clock = new CurrentClock,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	public function make(): LaunchRequestBuilder {
		$signer = (new RequestSignerFactory($this->nonceGenerator, $this->clock, $this->logger))->forMethod(SignatureMethod::HmacSha1);

		return new LaunchRequestBuilder($signer, $this->logger);
	}

}
