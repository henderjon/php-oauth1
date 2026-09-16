<?php

namespace BasicLti1;

/**
 * A fully-assembled Basic LTI launch, ready to submit as one POST: every launch parameter the
 * caller supplied, plus lti_message_type/lti_version, plus the oauth_* parameters
 * LaunchRequestBuilder produced.
 *
 * Deliberately holds data only, not markup. Basic LTI's own examples submit a launch as an
 * auto-submitting HTML form, but rendering one here would bake this library's opinion of a
 * `<script>` tag into every consumer, including one whose Content-Security-Policy requires a
 * nonce on every script tag that this library has no way to know. Turning
 * `$parameters` into hidden form fields is the consuming application's job.
 */
final class LaunchRequest {

	/**
	 * @param array<string,string> $parameters
	 */
	public function __construct(
		public readonly string $launchUrl,
		public readonly array $parameters,
	) {
	}

}
