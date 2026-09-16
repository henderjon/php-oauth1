<?php

namespace BasicLti1;

use BasicLti1\Exceptions\InvalidLaunchException;
use Oauth1\Credentials;
use Oauth1\Exceptions\RequestVerificationException;
use Oauth1\RequestVerifier;

/**
 * Verifies one incoming Basic LTI launch: checks the OAuth 1.0 signature first (delegated to the
 * injected RequestVerifier, which the spec requires to use HMAC-SHA1 - see
 * LaunchVerifierFactory), then that lti_message_type, lti_version, and resource_link_id are
 * present and correct. Authentication before content, deliberately - a request that is not who
 * it claims to be is not worth inspecting further.
 *
 * oauth_callback, if present, is stripped before OAuth verification, mirroring
 * LaunchRequestBuilder's choice not to sign it - see that class's docblock for why.
 *
 * @throws RequestVerificationException for a signature/timestamp/nonce failure - never caught or
 *         wrapped here, so a caller distinguishing OAuth failures from Basic LTI content
 *         failures can catch it directly.
 * @throws InvalidLaunchException for a missing/invalid Basic LTI parameter, once the signature
 *         itself has already checked out.
 */
final class LaunchVerifier {

	public function __construct(
		private readonly RequestVerifier $requestVerifier,
	) {
	}

	/**
	 * @param array<string,string|list<string>> $parameters Every parameter the launch POST
	 *                                                       carries, oauth_* ones included.
	 */
	public function verify( string $launchUrl, Credentials $credentials, array $parameters ): void {
		$signedParameters = $parameters;
		unset($signedParameters['oauth_callback']);

		$this->requestVerifier->verify('POST', $launchUrl, $credentials, $signedParameters);

		if ( ( $parameters[Launch::MESSAGE_TYPE_PARAM] ?? null ) !== Launch::MESSAGE_TYPE ) {
			throw new InvalidLaunchException(
				'Missing or invalid lti_message_type',
				LaunchValidationFailureReason::MissingOrInvalidMessageType,
			);
		}

		if ( ( $parameters[Launch::VERSION_PARAM] ?? null ) !== Launch::VERSION ) {
			throw new InvalidLaunchException(
				'Missing or invalid lti_version',
				LaunchValidationFailureReason::MissingOrInvalidVersion,
			);
		}

		if ( ( $parameters[Launch::RESOURCE_LINK_ID_PARAM] ?? '' ) === '' ) {
			throw new InvalidLaunchException(
				'A Basic LTI launch requires a non-empty resource_link_id',
				LaunchValidationFailureReason::MissingResourceLinkId,
			);
		}
	}

}
