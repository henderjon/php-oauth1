<?php

namespace Oauth1;

/**
 * RFC 5849 §3.4.2: HMAC-SHA1 over the signature base string, keyed by the consumer secret and
 * token secret (each percent-encoded per §3.6) joined by "&" - present even when one side is
 * empty, so a signing-only, one-legged request (no token secret at all) still has a key of
 * "secret&".
 */
final class HmacSha1Signer implements SignerInterface, VerifierInterface {

	public function method(): SignatureMethod {
		return SignatureMethod::HmacSha1;
	}

	public function sign( string $baseString, Credentials $credentials ): string {
		return base64_encode(hash_hmac('sha1', $baseString, $this->key($credentials), true));
	}

	public function verify( string $baseString, Credentials $credentials, string $signature ): bool {
		return hash_equals($this->sign($baseString, $credentials), $signature);
	}

	private function key( Credentials $credentials ): string {
		return PercentEncoding::encode($credentials->consumerSecret) . '&' . PercentEncoding::encode($credentials->tokenSecret);
	}

}
