<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Assembles a RequestSigner for one of the three RFC 5849 §3.4 signature methods, from a shared
 * clock, nonce generator, and logger - so a caller wiring up one signer per integration never
 * reaches for `new` on RequestSigner or its collaborators itself.
 *
 * RSA-SHA1 needs a private key; HMAC-SHA1 and PLAINTEXT sign with Credentials' own consumer/
 * token secrets instead - see forMethod()'s own docblock for exactly what each expects.
 */
final class RequestSignerFactory {

	public function __construct(
		private readonly NonceGeneratorInterface $nonceGenerator = new RandomNonceGenerator,
		private readonly ClockInterface $clock = new CurrentClock,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @param ?string $rsaPrivateKey Required, and used, only for SignatureMethod::RsaSha1 - a
	 *                               PEM-encoded RSA private key. Ignored for HMAC-SHA1 and
	 *                               PLAINTEXT, which sign with Credentials' own consumer/token
	 *                               secrets instead.
	 * @param string  $rsaPassphrase The private key's passphrase, when it has one. Ignored
	 *                               outside RSA-SHA1.
	 */
	public function forMethod( SignatureMethod $method, ?string $rsaPrivateKey = null, string $rsaPassphrase = '' ): RequestSigner {
		if ( $method === SignatureMethod::RsaSha1 && $rsaPrivateKey === null ) {
			$this->logger->error('oauth1.signer_factory_misconfigured', [
				'method' => $method->value,
				'security_relevant' => false,
			]);

			throw new SigningException('RSA-SHA1 requires a private key');
		}

		$signer = match ( $method ) {
			SignatureMethod::HmacSha1 => new HmacSha1Signer,
			SignatureMethod::Plaintext => new PlaintextSigner,
			SignatureMethod::RsaSha1 => new RsaSha1Signer($rsaPrivateKey, $rsaPassphrase, $this->logger),
		};

		return new RequestSigner($signer, $this->nonceGenerator, $this->clock, $this->logger);
	}

}
