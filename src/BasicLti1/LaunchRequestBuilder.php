<?php

namespace BasicLti1;

use BasicLti1\Exceptions\InvalidLaunchException;
use Oauth1\Credentials;
use Oauth1\RequestSigner;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Builds one Basic LTI launch: sets lti_message_type/lti_version (never left to the caller to
 * get right or wrong), requires resource_link_id, and signs the whole parameter set with the
 * injected RequestSigner - which the Basic LTI spec requires to use HMAC-SHA1 (see
 * LaunchRequestBuilderFactory).
 *
 * oauth_callback is added to the launch as a plain, unsigned parameter set to "about:blank" -
 * not passed through RequestSigner's own `$callback` argument, and so not part of the signature
 * base string at all. This is deliberate, not an oversight: the Basic LTI v1.0 Implementation
 * Guide's own reference launch example (Appendix B) includes oauth_callback as a submitted form
 * field but excludes it from the base string it signs, and that example's own printed
 * oauth_signature only reproduces when this class does the same. RFC 5849 §3.4.1.3.1 would
 * include it if strictly followed, but matching the spec's own worked example - and the many
 * real Tool Consumers that copied it - is the more useful behavior for interoperating with
 * actual Basic LTI traffic. LaunchVerifier makes the matching choice on the receiving side.
 */
final class LaunchRequestBuilder {

	public function __construct(
		private readonly RequestSigner $signer,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @param array<string,string> $launchParameters Every other launch parameter (resource_link_id
	 *                                                required; context/user/role/custom/ext_
	 *                                                parameters as needed) - lti_message_type and
	 *                                                lti_version are set here regardless of
	 *                                                whether the caller also supplied them.
	 *
	 * @throws InvalidLaunchException
	 */
	public function build( string $launchUrl, Credentials $credentials, array $launchParameters ): LaunchRequest {
		// isValidResourceLinkId() takes `mixed`, not the array's own declared `string` value
		// type - $launchParameters is documented as array<string,string>, but nothing in PHP
		// enforces that shape at a caller's own call site (a caller building it from decoded
		// JSON/form data, say), so this checks the real runtime value rather than trusting the
		// PHPDoc contract at the one place it actually matters - mirroring LaunchVerifier's own
		// guard on the receiving side, where the same value can genuinely arrive as an array.
		if ( ! $this->isValidResourceLinkId($launchParameters[Launch::RESOURCE_LINK_ID_PARAM] ?? '') ) {
			$this->logger->error('basiclti1.launch_build_failed', [
				'consumer_key' => $credentials->consumerKey,
				'reason' => LaunchValidationFailureReason::MissingResourceLinkId->name,
				'security_relevant' => false,
			]);

			throw new InvalidLaunchException(
				'A Basic LTI launch requires a non-empty resource_link_id',
				LaunchValidationFailureReason::MissingResourceLinkId,
				$credentials->consumerKey,
			);
		}

		// Overriding lti_message_type/lti_version below always lets this method win a
		// collision silently - this is the only place that says a caller-supplied value
		// actually got replaced, mirroring Oidc's own "extraAuthParams collided with a
		// reserved param" debug.
		$overriddenKeys = array_values(array_filter(
			[ Launch::MESSAGE_TYPE_PARAM, Launch::VERSION_PARAM ],
			fn ( string $key ) => isset($launchParameters[$key]) && $launchParameters[$key] !== ( $key === Launch::MESSAGE_TYPE_PARAM ? Launch::MESSAGE_TYPE : Launch::VERSION ),
		));

		if ( $overriddenKeys !== [] ) {
			$this->logger->debug('basiclti1.reserved_parameter_overridden', [
				'consumer_key' => $credentials->consumerKey,
				'overridden_keys' => $overriddenKeys,
			]);
		}

		$launchParameters[Launch::MESSAGE_TYPE_PARAM] = Launch::MESSAGE_TYPE;
		$launchParameters[Launch::VERSION_PARAM]      = Launch::VERSION;

		$signed = $this->signer->sign('POST', $launchUrl, $credentials, $launchParameters);

		$this->logger->debug('basiclti1.launch_built', [
			'consumer_key' => $credentials->consumerKey,
			'resource_link_id' => $launchParameters[Launch::RESOURCE_LINK_ID_PARAM],
		]);

		return new LaunchRequest(
			$launchUrl,
			[
				...$launchParameters,
				...$signed->oauthParameters,
				'oauth_callback' => 'about:blank',
			],
			$signed->baseStringSha256,
		);
	}

	private function isValidResourceLinkId( mixed $value ): bool {
		return is_string($value) && $value !== '';
	}

}
