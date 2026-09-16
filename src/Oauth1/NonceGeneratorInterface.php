<?php

namespace Oauth1;

/**
 * Produces the `oauth_nonce` value RFC 5849 §3.3 requires: unique per timestamp/consumer-key/
 * token combination. Injectable so a test can assert against a fixed nonce instead of a random
 * one.
 */
interface NonceGeneratorInterface {

	public function generate(): string;

}
