<?php

namespace Oauth1;

/**
 * One RFC 5849 §3.4 signature method's verifying half. See SignerInterface - the same reasoning
 * applies to RequestVerifier.
 */
interface VerifierInterface {

	public function method(): SignatureMethod;

	public function verify( string $baseString, Credentials $credentials, string $signature ): bool;

}
