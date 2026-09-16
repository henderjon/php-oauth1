<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * RFC 5849 §3.4.3: RSASSA-PKCS1-v1_5 over the signature base string, using SHA-1 and the
 * client's own RSA private key - never a shared secret. Pair this with RsaSha1Verifier,
 * constructed from the matching public key, on whichever side checks the signature; one key
 * material never signs and verifies through the same object, since the RFC only issues a client
 * its private key.
 */
final class RsaSha1Signer implements SignerInterface {

	/**
	 * @param string $privateKey The key's own PEM content (e.g. `file_get_contents('key.pem')`),
	 *                            not a path to it - `openssl_pkey_get_private()` also accepts a
	 *                            `file://`-prefixed path as an incidental consequence of PHP's
	 *                            stream wrapper support, since this class passes `$privateKey`
	 *                            straight through untouched, but that is not this constructor's
	 *                            documented contract, only openssl's own. A bare filename with no
	 *                            scheme is not a path at all here - openssl treats it as literal,
	 *                            invalid key content and this fails exactly like any other
	 *                            unreadable key.
	 */
	public function __construct(
		private readonly string $privateKey,
		private readonly string $passphrase = '',
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	public function method(): SignatureMethod {
		return SignatureMethod::RsaSha1;
	}

	public function sign( string $baseString, Credentials $credentials ): string {
		$key = openssl_pkey_get_private($this->privateKey, $this->passphrase);
		if ( $key === false ) {
			$this->fail('RSA-SHA1 signing failed: private key could not be read', $credentials);
		}

		$signature = '';
		if ( ! openssl_sign($baseString, $signature, $key, OPENSSL_ALGO_SHA1) ) {
			$this->fail('RSA-SHA1 signing failed: openssl_sign() rejected the base string or key', $credentials);
		}

		$this->logger->debug('oauth1.rsa_sha1_signed', [ 'consumer_key' => $credentials->consumerKey ]);

		return base64_encode($signature);
	}

	private function fail( string $message, Credentials $credentials ): never {
		$this->logger->error('oauth1.signing_failed', [
			'consumer_key' => $credentials->consumerKey,
			// See PemPreview's own docblock for why this is safe: a PEM header is fixed
			// boilerplate, never derived from the key's own bytes.
			'private_key_pem_header' => PemPreview::headerLine($this->privateKey),
			'security_relevant' => false,
		]);

		throw new SigningException($message, $credentials->consumerKey);
	}

}
