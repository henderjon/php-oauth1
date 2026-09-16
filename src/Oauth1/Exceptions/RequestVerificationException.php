<?php

namespace Oauth1\Exceptions;

use Oauth1\VerificationFailureReason;

/**
 * Thrown by RequestVerifier for any reason a request fails verification - see
 * VerificationFailureReason for the full list. Fail-closed: every one of these reasons throws
 * rather than returning a falsy result a caller could forget to check.
 */
class RequestVerificationException extends OAuth1Exception {

	public function __construct(
		string $message,
		private readonly VerificationFailureReason $reason,
		?\Throwable $previous = null,
	) {
		parent::__construct($message, previous: $previous);
	}

	public function getReason(): VerificationFailureReason {
		return $this->reason;
	}

}
