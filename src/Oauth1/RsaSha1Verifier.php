<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * The verifying half of RSA-SHA1 (RFC 5849 §3.4.3): checks a signature against the client's RSA
 * public key. See RsaSha1Signer's docblock for why these are two classes, not one.
 */
final class RsaSha1Verifier implements VerifierInterface {

	/**
	 * @param string $publicKey The key's own PEM content, not a path to it - see
	 *                           RsaSha1Signer's matching constructor docblock for the exact
	 *                           same reasoning, applied to `openssl_pkey_get_public()` here.
	 */
	public function __construct(
		private readonly string $publicKey,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	public function method(): SignatureMethod {
		return SignatureMethod::RsaSha1;
	}

	public function verify( string $baseString, Credentials $credentials, string $signature ): bool {
		$key = openssl_pkey_get_public($this->publicKey);
		if ( $key === false ) {
			// 'oauth1.verifying_failed', not 'oauth1.signing_failed' - see RequestVerifier's
			// matching comment for why the two are named apart, rather than conflating "a
			// SigningException was thrown" with "the signing side specifically failed."
			$this->logger->error('oauth1.verifying_failed', [
				'consumer_key' => $credentials->consumerKey,
				// See PemPreview's own docblock for why this is safe (built only from the PEM
				// format's own fixed boilerplate) and why it also checks for the footer, not
				// just the header - a truncated key keeps its header fully intact.
				'public_key_pem' => PemPreview::describe($this->publicKey),
				'security_relevant' => false,
			]);

			throw new SigningException('RSA-SHA1 verification failed: public key could not be read', $credentials->consumerKey);
		}

		$this->logger->debug('oauth1.rsa_sha1_key_loaded', [ 'consumer_key' => $credentials->consumerKey ]);

		$decodedSignature = base64_decode($signature, true);
		if ( $decodedSignature === false ) {
			return false;
		}

		return openssl_verify($baseString, $decodedSignature, $key, OPENSSL_ALGO_SHA1) === 1;
	}

}
