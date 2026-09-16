<?php

namespace BasicLti1;

use BasicLti1\Exceptions\InvalidLaunchException;
use Oauth1\Credentials;
use Oauth1\Exceptions\RequestVerificationException;
use Oauth1\RequestVerifier;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

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
 * Every content failure below logs an `error()` immediately before throwing, with
 * `security_relevant` always `false` - once the signature has already checked out, a wrong
 * lti_message_type/lti_version or a missing resource_link_id is a non-conformant Tool Consumer,
 * not tampering; the signature check is what would have caught tampering, and that check
 * (RequestVerifier's own) already logs `true` for the two reasons that actually warrant it. See
 * RequestVerifier's docblock for the same reasoning applied to Oauth1 itself.
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
		private readonly LoggerInterface $logger = new NullLogger,
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
			$this->fail('Missing or invalid lti_message_type', LaunchValidationFailureReason::MissingOrInvalidMessageType, $credentials);
		}

		if ( ( $parameters[Launch::VERSION_PARAM] ?? null ) !== Launch::VERSION ) {
			$this->fail('Missing or invalid lti_version', LaunchValidationFailureReason::MissingOrInvalidVersion, $credentials);
		}

		if ( ( $parameters[Launch::RESOURCE_LINK_ID_PARAM] ?? '' ) === '' ) {
			$this->fail('A Basic LTI launch requires a non-empty resource_link_id', LaunchValidationFailureReason::MissingResourceLinkId, $credentials);
		}

		$this->logger->debug('basiclti1.launch_verified', [
			'consumer_key' => $credentials->consumerKey,
			'resource_link_id' => $parameters[Launch::RESOURCE_LINK_ID_PARAM],
		]);
	}

	private function fail( string $message, LaunchValidationFailureReason $reason, Credentials $credentials ): never {
		$this->logger->error('basiclti1.launch_verification_failed', [
			'consumer_key' => $credentials->consumerKey,
			'reason' => $reason->name,
			'security_relevant' => false,
		]);

		throw new InvalidLaunchException($message, $reason);
	}

}
