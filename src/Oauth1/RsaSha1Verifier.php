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

		$result = openssl_verify($baseString, $decodedSignature, $key, OPENSSL_ALGO_SHA1);
		if ( $result === -1 ) {
			// openssl_verify() returns -1, not just 0, when it rejects the input itself (e.g. a
			// key of the wrong type/algorithm for OPENSSL_ALGO_SHA1) rather than computing a
			// signature and finding it did not match. Collapsing -1 into the same `false` as an
			// ordinary mismatch would report a key/config problem as a failed signature check -
			// logged with security_relevant: true by RequestVerifier, a false attack signal for
			// what is actually a misconfiguration. SigningException's own docblock says this
			// exact case ("openssl itself rejecting the input") belongs here, not as a returned
			// `false`.
			$this->logger->error('oauth1.verifying_failed', [
				'consumer_key' => $credentials->consumerKey,
				'openssl_error' => openssl_error_string() ?: null,
				'security_relevant' => false,
			]);

			throw new SigningException('RSA-SHA1 verification failed: openssl rejected the input', $credentials->consumerKey);
		}

		return $result === 1;
	}

}
