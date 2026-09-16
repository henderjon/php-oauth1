<?php

namespace Oauth1;

/**
 * RFC 5849 §3.4.4: no signature algorithm at all - `oauth_signature` is just the consumer secret
 * and token secret (each percent-encoded), joined by "&". MUST only be used over TLS; this class
 * has no way to enforce that, so whatever constructs a PlaintextSigner is the thing responsible
 * for it.
 */
final class PlaintextSigner implements SignerInterface, VerifierInterface {

	public function method(): SignatureMethod {
		return SignatureMethod::Plaintext;
	}

	public function sign( string $baseString, Credentials $credentials ): string {
		return PercentEncoding::encode($credentials->consumerSecret) . '&' . PercentEncoding::encode($credentials->tokenSecret);
	}

	public function verify( string $baseString, Credentials $credentials, string $signature ): bool {
		return hash_equals($this->sign($baseString, $credentials), $signature);
	}

}
