<?php

namespace Oauth1\Exceptions;

class OAuth1Exception extends \RuntimeException {

	public function __construct(
		string $message = '',
		private readonly ?string $consumerKey = null,
		?\Throwable $previous = null,
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

}
