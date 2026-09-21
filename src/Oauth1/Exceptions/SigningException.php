<?php

namespace Oauth1\Exceptions;

/**
 * Thrown when a signer or verifier cannot even attempt a signature - a malformed URL with no
 * scheme or host to build a base string URI from, an unreadable RSA key, or openssl itself
 * rejecting the input. Never thrown for a signature that was computed and simply did not match -
 * that is RequestVerificationException's job.
 */
class SigningException extends OAuth1Exception {

	public function __construct(
		string $message = '',
		?string $consumerKey = null,
		?\Throwable $previous = null,
		private readonly ?string $baseStringSha256 = null,
	) {
		parent::__construct($message, $consumerKey, $previous);
	}

	/**
	 * The SHA-256 hash RequestVerifier's own `baseString()` already computed for this call, when
	 * the nonce store failed to persist its claim after that computation succeeded - null for
	 * every other SigningException, since a malformed URL and SignatureBaseString::build()
	 * itself failing both mean no base string ever existed to hash.
	 */
	public function getBaseStringSha256(): ?string {
		return $this->baseStringSha256;
	}

}
