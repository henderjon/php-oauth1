<?php

namespace Oauth1;

use Oauth1\Exceptions\RequestVerificationException;
use Oauth1\Exceptions\SigningException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Verifies one incoming request: recomputes its signature from the parameters the caller
 * already parsed and compares it, checks `oauth_version` when present, and - for HMAC-SHA1/
 * RSA-SHA1 - rejects a timestamp outside the configured tolerance or a nonce already claimed by
 * NonceStore (RFC 5849 §3.2, §3.3).
 *
 * Every failure throws RequestVerificationException rather than returning false - fail-closed,
 * so a caller cannot accidentally treat "did not check" the same as "checked and passed". Every
 * one of those failures also logs an `error()` immediately before throwing, carrying a
 * `security_relevant` boolean: `true` only for InvalidSignature and NonceReplayed, the two
 * outcomes that are essentially unexplainable except as tampering or a replay attempt - every
 * other reason (a missing parameter, an unsupported version/method, a mismatched consumer key,
 * a timestamp outside tolerance) is `false`, since each is just as plausibly a caller mistake,
 * a stale integration, or ordinary clock skew as an attack. This mirrors Oidc's own
 * ClaimsValidator/IdTokenVerifier, where the curated `true` list is similarly small (signature
 * failure, `alg: none`, nonce mismatch) and an expired-token or audience-mismatch check is
 * `false` despite sounding just as security-relevant.
 *
 * `$credentials` must already carry the consumer secret (and token secret, if any) the caller
 * looked up for the incoming `oauth_consumer_key` - this class does not know how or where that
 * lookup happens, the same way Oidc's collaborators never look up a client's own registration
 * themselves.
 *
 * Every PLAINTEXT verify() call also logs an `alert` - see RequestSigner's docblock for why, and
 * why every call, not just once.
 *
 * `oauth_consumer_key` is taken straight from the incoming, not-yet-validated request and is
 * unbounded in length until it has been checked against `$credentials->consumerKey`. Only the
 * copy that goes into a *log line* is length-capped (`loggableConsumerKey()`) - both the value a
 * security comparison runs against and the value RequestVerificationException/SigningException
 * actually carry stay full and untruncated. Handing back a silently-truncated key that no
 * longer matches anything in the caller's own store, after the caller looked up `$credentials`
 * by that same key before ever calling `verify()`, would be a functional bug hiding behind a
 * security-sounding justification, not a property worth having - a caller may reasonably want
 * the real value after catching a failure, to rate-limit a specific consumer or notify whoever
 * owns it.
 *
 * The cap itself (MAX_LOGGED_CONSUMER_KEY_LENGTH) is 255, not the 64 Oidc\AuthorizationStateStore
 * uses for its own `state` - deliberately not copied without checking why 64 was right there.
 * `state` is a value that library generates itself (`bin2hex(random_bytes(16))` by default, 32
 * hex characters), so 64 is a safety margin over a length the library actually controls. RFC
 * 5849 places no length limit on `oauth_consumer_key` at all, and this library never generates
 * one - it is assigned by whoever registers a Tool Consumer, the same kind of externally
 * assigned, unbounded-until-validated value as an OIDC callback's own `error`/
 * `error_description` (`Oidc\IncomingAuthorizationResponse::MAX_ERROR_FIELD_LENGTH`, also 255),
 * not `state`.
 */
final class RequestVerifier {

	private const MAX_LOGGED_CONSUMER_KEY_LENGTH = 255;

	public function __construct(
		private readonly VerifierInterface $verifier,
		private readonly NonceStore $nonceStore,
		private readonly ClockInterface $clock = new CurrentClock,
		private readonly int $timestampToleranceSeconds = 300,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @param array<string,string|list<string>> $parameters Every parameter the request carries,
	 *                                                       from every source RFC 5849
	 *                                                       §3.4.1.3.1 lists (URI query,
	 *                                                       `Authorization` header minus
	 *                                                       `realm`, form-encoded body) - the
	 *                                                       `oauth_*` ones included, already
	 *                                                       decoded to their original values.
	 *
	 * @throws RequestVerificationException
	 */
	public function verify( string $httpMethod, string $url, Credentials $credentials, array $parameters ): void {
		$oauthConsumerKey = $this->requireScalarParameter($parameters, 'oauth_consumer_key', null);
		$signatureMethod  = $this->requireScalarParameter($parameters, 'oauth_signature_method', $oauthConsumerKey);
		$signature        = $this->requireScalarParameter($parameters, 'oauth_signature', $oauthConsumerKey);

		$oauthVersion = $parameters['oauth_version'] ?? '1.0';
		if ( $oauthVersion !== '1.0' ) {
			$shown = is_string($oauthVersion) ? $oauthVersion : 'a repeated parameter';
			$this->fail("Unsupported oauth_version \"$shown\"", VerificationFailureReason::UnsupportedVersion, false, $oauthConsumerKey);
		}

		if ( $signatureMethod !== $this->verifier->method()->value ) {
			$this->fail(
				"Request signed with \"$signatureMethod\", this verifier only accepts \"{$this->verifier->method()->value}\"",
				VerificationFailureReason::UnsupportedSignatureMethod,
				false,
				$oauthConsumerKey,
			);
		}

		if ( $oauthConsumerKey !== $credentials->consumerKey ) {
			$this->fail(
				'oauth_consumer_key does not match the credentials looked up for this request',
				VerificationFailureReason::ConsumerKeyMismatch,
				false,
				$oauthConsumerKey,
			);
		}

		if ( $this->verifier->method() === SignatureMethod::Plaintext ) {
			$this->logger->alert('oauth1.plaintext_method_used', [ 'consumer_key' => $this->loggableConsumerKey($oauthConsumerKey) ]);
		} else {
			$this->verifyTimestampAndNonce($parameters, $credentials);
		}

		$baseString = $this->verifier->method() === SignatureMethod::Plaintext
			? ''
			: $this->baseString($httpMethod, $url, $parameters, $oauthConsumerKey);

		if ( ! $this->verifier->verify($baseString, $credentials, $signature) ) {
			$this->fail('Signature does not match', VerificationFailureReason::InvalidSignature, true, $oauthConsumerKey);
		}

		$this->logger->debug('oauth1.request_verified', [ 'consumer_key' => $this->loggableConsumerKey($oauthConsumerKey) ]);
	}

	/**
	 * @param array<string,string|list<string>> $parameters
	 */
	private function verifyTimestampAndNonce( array $parameters, Credentials $credentials ): void {
		$timestamp = $this->requireScalarParameter($parameters, 'oauth_timestamp', $credentials->consumerKey);
		$nonce     = $this->requireScalarParameter($parameters, 'oauth_nonce', $credentials->consumerKey);

		$age = abs($this->clock->now()->getTimestamp() - (int) $timestamp);
		if ( $age > $this->timestampToleranceSeconds ) {
			$this->fail(
				"Timestamp \"$timestamp\" is outside the {$this->timestampToleranceSeconds}s tolerance",
				VerificationFailureReason::TimestampOutOfWindow,
				false,
				$credentials->consumerKey,
			);
		}

		if ( ! $this->nonceStore->claim($credentials->consumerKey, $credentials->token, $nonce, $timestamp, $this->timestampToleranceSeconds) ) {
			$this->fail('Nonce has already been used', VerificationFailureReason::NonceReplayed, true, $credentials->consumerKey);
		}
	}

	/**
	 * @param array<string,string|list<string>> $parameters
	 */
	private function baseString( string $httpMethod, string $url, array $parameters, string $consumerKey ): string {
		try {
			$baseString = SignatureBaseString::build($httpMethod, $url, $this->withoutSignature($parameters));
		} catch ( SigningException $exception ) {
			// Rewrapped, not rethrown as-is: SignatureBaseString has no Credentials in scope to
			// attach a consumer key to its own exception, but this layer does - the same
			// boundary-attach pattern as Oidc\OpenIDConnectClient wrapping a lower-level
			// AuthenticationFailedException to add the ID token it has and the collaborator
			// that threw did not. Constructed before logging, not after - see
			// RequestSigner::baseString()'s matching comment for why. Carries the full,
			// untruncated $consumerKey - a caller catching this may need the real value to
			// look something up in its own store; only the *log line* is length-capped, per
			// this class's own docblock, never what a caller actually receives.
			$rewrapped = new SigningException($exception->getMessage(), $consumerKey, $exception);

			// 'oauth1.verifying_failed', not 'oauth1.signing_failed' - this happens on the
			// verifying side, and a consumer filtering log events by name on "which side had a
			// broken key/base string" should not see the two conflated under a name that reads
			// as sign-side specific. RequestSigner's matching catch block is the one place that
			// legitimately logs 'oauth1.signing_failed' for this same exception type.
			$this->logger->error('oauth1.verifying_failed', [
				'consumer_key' => $this->loggableConsumerKey($consumerKey),
				'exception' => $rewrapped,
				'security_relevant' => false,
			]);

			throw $rewrapped;
		}

		// The base string can carry values a caller supplied - Basic LTI's own launch
		// parameters include PII (lis_person_name_full, lis_person_contact_email_primary) -
		// and this class has no way to know which, if any, of an arbitrary caller's
		// $requestParameters are sensitive the way Oidc\TokenEndpointClient's own
		// SENSITIVE_PARAM_KEYS can, since that list is only possible because OIDC defines a
        // fixed parameter vocabulary this library owns. A hash preserves the one thing this
		// log line exists for - telling whether two parties built the identical base string,
		// by comparing this value across their two logs - without ever putting the content
		// itself, PII included, into a log store.
		$this->logger->debug('oauth1.signature_base_string_built', [
			'consumer_key' => $this->loggableConsumerKey($consumerKey),
			'base_string_sha256' => hash('sha256', $baseString),
		]);

		return $baseString;
	}

	/**
	 * @param array<string,string|list<string>> $parameters
	 * @return array<string,string|list<string>>
	 */
	private function withoutSignature( array $parameters ): array {
		unset($parameters['oauth_signature']);

		return $parameters;
	}

	/**
	 * @param array<string,string|list<string>> $parameters
	 */
	private function requireScalarParameter( array $parameters, string $name, ?string $consumerKey ): string {
		$value = $parameters[$name] ?? null;
		if ( ! is_string($value) || $value === '' ) {
			$this->fail("Missing required parameter \"$name\"", VerificationFailureReason::MissingParameter, false, $consumerKey);
		}

		return $value;
	}

	private function fail( string $message, VerificationFailureReason $reason, bool $securityRelevant, ?string $consumerKey ): never {
		$this->logger->error('oauth1.verification_failed', [
			'reason' => $reason->name,
			'consumer_key' => $this->loggableConsumerKey($consumerKey),
			'security_relevant' => $securityRelevant,
		]);

		// Full, untruncated $consumerKey - not $this->loggableConsumerKey($consumerKey) above.
		// A caller catching this may need the real value (to look something up in its own
		// store, say); only the log line just above is length-capped. See this class's own
		// docblock for why only the logged/thrown-*to-the-log* copy is ever capped, never what
		// calling code actually receives.
		throw new RequestVerificationException($message, $reason, $consumerKey);
	}

	/**
	 * Caps the incoming, not-yet-validated `oauth_consumer_key` at
	 * MAX_LOGGED_CONSUMER_KEY_LENGTH before it goes anywhere - a log line or an exception - that
	 * this class does not control the eventual size of. See this class's own docblock for why
	 * only this copy is capped, never the value a comparison runs against.
	 */
	private function loggableConsumerKey( ?string $consumerKey ): ?string {
		return $consumerKey === null ? null : Truncate::to($consumerKey, self::MAX_LOGGED_CONSUMER_KEY_LENGTH);
	}

}
