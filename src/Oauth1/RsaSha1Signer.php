<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;

/**
 * RFC 5849 §3.4.3: RSASSA-PKCS1-v1_5 over the signature base string, using SHA-1 and the
 * client's own RSA private key - never a shared secret. Pair this with RsaSha1Verifier,
 * constructed from the matching public key, on whichever side checks the signature; one key
 * material never signs and verifies through the same object, since the RFC only issues a client
 * its private key.
 */
final class RsaSha1Signer implements SignerInterface {

	public function __construct(
		private readonly string $privateKey,
		private readonly string $passphrase = '',
	) {
	}

	public function method(): SignatureMethod {
		return SignatureMethod::RsaSha1;
	}

	public function sign( string $baseString, Credentials $credentials ): string {
		$key = openssl_pkey_get_private($this->privateKey, $this->passphrase);
		if ( $key === false ) {
			throw new SigningException('RSA-SHA1 signing failed: private key could not be read');
		}

		$signature = '';
		if ( ! openssl_sign($baseString, $signature, $key, OPENSSL_ALGO_SHA1) ) {
			throw new SigningException('RSA-SHA1 signing failed: openssl_sign() rejected the base string or key');
		}

		return base64_encode($signature);
	}

}
