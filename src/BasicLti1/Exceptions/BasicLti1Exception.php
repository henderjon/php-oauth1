<?php

namespace BasicLti1\Exceptions;

class BasicLti1Exception extends \RuntimeException {

	public function __construct(
		string $message = '',
		private readonly ?string $consumerKey = null,
		?\Throwable $previous = null,
	) {
		parent::__construct($message, previous: $previous);
	}

	/**
	 * The `oauth_consumer_key` this failure happened against, when one was in scope - null for a
	 * failure with nothing yet to correlate with (see Oauth1\Exceptions\OAuth1Exception's own
	 * docblock, which this mirrors).
	 */
	public function getConsumerKey(): ?string {
		return $this->consumerKey;
	}

}
