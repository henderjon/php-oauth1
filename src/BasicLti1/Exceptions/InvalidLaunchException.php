<?php

namespace BasicLti1\Exceptions;

use BasicLti1\LaunchValidationFailureReason;

/**
 * Thrown when a launch is missing or carries the wrong value for lti_message_type,
 * lti_version, or resource_link_id - the three parameters Basic LTI itself requires,
 * independent of whether the request was signed correctly. See
 * Oauth1\Exceptions\RequestVerificationException for a launch that fails OAuth 1.0
 * verification instead; LaunchVerifier checks that first and lets it propagate uncaught.
 */
class InvalidLaunchException extends BasicLti1Exception {

	public function __construct(
		string $message,
		private readonly LaunchValidationFailureReason $reason,
		?string $consumerKey = null,
		?\Throwable $previous = null,
	) {
		parent::__construct($message, $consumerKey, $previous);
	}

	public function getReason(): LaunchValidationFailureReason {
		return $this->reason;
	}

}
