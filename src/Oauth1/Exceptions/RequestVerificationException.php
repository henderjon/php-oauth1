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
		?string $consumerKey = null,
		?\Throwable $previous = null,
		private readonly ?string $baseStringSha256 = null,
	) {
		parent::__construct($message, $consumerKey, $previous);
	}

	public function getReason(): VerificationFailureReason {
		return $this->reason;
	}

	/**
	 * The SHA-256 hash RequestVerifier's own `baseString()` already computed for this call, when
	 * this failure (InvalidSignature, NonceReplayed) happened after that computation succeeded -
	 * null for every other VerificationFailureReason, since each of those is caught before
	 * `baseString()` ever runs.
	 */
	public function getBaseStringSha256(): ?string {
		return $this->baseStringSha256;
	}

}
