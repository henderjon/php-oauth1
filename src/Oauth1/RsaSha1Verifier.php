<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;

/**
 * The verifying half of RSA-SHA1 (RFC 5849 §3.4.3): checks a signature against the client's RSA
 * public key. See RsaSha1Signer's docblock for why these are two classes, not one.
 */
final class RsaSha1Verifier implements VerifierInterface {

	public function __construct(
		private readonly string $publicKey,
	) {
	}

	public function method(): SignatureMethod {
		return SignatureMethod::RsaSha1;
	}

	public function verify( string $baseString, Credentials $credentials, string $signature ): bool {
		$key = openssl_pkey_get_public($this->publicKey);
		if ( $key === false ) {
			throw new SigningException('RSA-SHA1 verification failed: public key could not be read');
		}

		$decodedSignature = base64_decode($signature, true);
		if ( $decodedSignature === false ) {
			return false;
		}

		return openssl_verify($baseString, $decodedSignature, $key, OPENSSL_ALGO_SHA1) === 1;
	}

}
