<?php

namespace Oauth1\Exceptions;

class OAuth1Exception extends \RuntimeException {

	public function __construct(
		string $message = '',
		private readonly ?string $consumerKey = null,
		?\Throwable $previous = null,
		private readonly ?string $baseStringSha256 = null,
	) {
		parent::__construct($message, previous: $previous);
	}

	/**
	 * The `oauth_consumer_key` this failure happened against, when one was in scope - null for a
	 * failure with nothing yet to correlate with (a malformed URL passed to
	 * SignatureBaseString, or a factory misconfigured before any specific request is in play).
	 */
	public function getConsumerKey(): ?string {
		return $this->consumerKey;
	}

	/**
	 * The SHA-256 hash RequestSigner/RequestVerifier's own `baseString()` already computed for
	 * this call, when this failure happened after that computation succeeded - null when the base
	 * string was never built (a malformed URL, or a failure that happened before `baseString()`
	 * ran at all, e.g. a missing parameter). This is the one piece of diagnostic data worth
	 * keeping past the happy path - RequestSigner/RequestVerifier do not log it themselves, since
	 * a caller comparing what two parties computed only needs it once something has already
	 * failed, never on every successful call.
	 */
	public function getBaseStringSha256(): ?string {
		return $this->baseStringSha256;
	}

}
