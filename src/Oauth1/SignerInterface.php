<?php

namespace Oauth1;

/**
 * One RFC 5849 §3.4 signature method's signing half. RequestSigner depends on this, not a
 * concrete signer, so choosing HMAC-SHA1 vs RSA-SHA1 vs PLAINTEXT is a constructor argument,
 * never a branch inside RequestSigner itself.
 */
interface SignerInterface {

	public function method(): SignatureMethod;

	public function sign( string $baseString, Credentials $credentials ): string;

}
