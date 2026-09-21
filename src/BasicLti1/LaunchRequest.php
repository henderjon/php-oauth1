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
	 * @param ?string $baseStringSha256 The SHA-256 hash of the signature base string this
	 *                                  launch's underlying Oauth1\SignedRequest was built from -
	 *                                  carried straight through from Oauth1\RequestSigner::sign(),
	 *                                  since Basic LTI is hard-wired to HMAC-SHA1
	 *                                  (LaunchRequestBuilderFactory), never PLAINTEXT, so this is
	 *                                  never actually null in practice for a launch this class
	 *                                  builds - null stays possible only because it mirrors
	 *                                  SignedRequest's own nullable type.
	 */
	public function __construct(
		public readonly string $launchUrl,
		public readonly array $parameters,
		public readonly ?string $baseStringSha256 = null,
	) {
	}

}
