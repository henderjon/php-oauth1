<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * Assembles a RequestVerifier for one of the three RFC 5849 §3.4 signature methods, from a
 * shared clock and logger and a per-call nonce cache - so a caller wiring up one verifier per
 * integration never reaches for `new` on RequestVerifier, NonceStore, or a concrete
 * VerifierInterface itself.
 *
 * RSA-SHA1 needs the client's public key; HMAC-SHA1 and PLAINTEXT verify against Credentials'
 * own consumer/token secrets instead - see forMethod()'s own docblock for exactly what each
 * expects.
 */
final class RequestVerifierFactory {

	public function __construct(
		private readonly ClockInterface $clock = new CurrentClock,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @param ?string $rsaPublicKey Required, and used, only for SignatureMethod::RsaSha1 - a
	 *                              PEM-encoded RSA public key. Ignored for HMAC-SHA1 and
	 *                              PLAINTEXT, which verify against Credentials' own consumer/
	 *                              token secrets instead.
	 */
	public function forMethod(
		SignatureMethod $method,
		CacheInterface $nonceCache,
		string $cacheKeySuffix = '',
		int $timestampToleranceSeconds = 300,
		?string $rsaPublicKey = null,
	): RequestVerifier {
		if ( $method === SignatureMethod::RsaSha1 && $rsaPublicKey === null ) {
			$this->logger->error('oauth1.verifier_factory_misconfigured', [
				'method' => $method->value,
				'security_relevant' => false,
			]);

			throw new SigningException('RSA-SHA1 requires a public key');
		}

		$verifier = match ( $method ) {
			SignatureMethod::HmacSha1 => new HmacSha1Signer,
			SignatureMethod::Plaintext => new PlaintextSigner,
			SignatureMethod::RsaSha1 => new RsaSha1Verifier($rsaPublicKey, $this->logger),
		};

		return new RequestVerifier(
			$verifier,
			new NonceStore($nonceCache, $cacheKeySuffix),
			$this->clock,
			$timestampToleranceSeconds,
			$this->logger,
		);
	}

}
