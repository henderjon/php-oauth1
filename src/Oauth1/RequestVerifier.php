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
 * The nonce is claimed only *after* the signature has been proven genuine, deliberately not the
 * other way around. `oauth_nonce`, `oauth_timestamp`, and `oauth_consumer_key` are all plaintext
 * request parameters, visible to anyone who can see the wire - claiming first would let an
 * attacker who cannot sign anything still burn a legitimate nonce by sending a request with a
 * garbage `oauth_signature` but a copied nonce/timestamp/consumer key, turning RFC 5849 §3.3's
 * own replay protection into a denial-of-service vector against the legitimate request that
 * nonce belonged to.
 *
 * Every protocol-level failure - a bad signature, a mismatched consumer key, a stale timestamp,
 * a replayed nonce - throws RequestVerificationException rather than returning false -
 * fail-closed, so a caller cannot accidentally treat "did not check" the same as "checked and
 * passed". A failure that means this class could not even attempt or complete the check at all -
 * a malformed URL, the nonce store's own cache failing to persist a claim, or the injected
 * VerifierInterface itself throwing one (RsaSha1Verifier does, for an unreadable key or
 * openssl_verify() rejecting the input) - throws SigningException instead, propagated unmodified
 * from wherever it actually originated; see that type's own docblock for why the two are kept
 * apart. Every
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

	/**
	 * @param int $timestampToleranceSeconds Not validated against zero or negative - both fail
	 *                                        closed rather than open. Zero means exact-match
	 *                                        only; negative means `age > tolerance` is always
	 *                                        true (`age` is never negative), so every request is
	 *                                        rejected as TimestampOutOfWindow before nonce
	 *                                        claiming ever runs. An unvalidated misconfiguration,
	 *                                        not a security gap.
	 */
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
	 * @throws RequestVerificationException a protocol-level failure - see VerificationFailureReason.
	 * @throws SigningException a malformed $url, the nonce store failing to persist a claim, or
	 *                          the injected VerifierInterface itself throwing one (RsaSha1Verifier
	 *                          does, for an unreadable public key or openssl_verify() rejecting
	 *                          the input outright) - propagated unmodified, not caught here. Every
	 *                          case means this class could not even attempt or complete the
	 *                          check, not that it ran the check and failed it.
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

		$isPlaintext = $this->verifier->method() === SignatureMethod::Plaintext;

		if ( $isPlaintext ) {
			$this->logger->alert('oauth1.plaintext_method_used', [ 'consumer_key' => $this->loggableConsumerKey($oauthConsumerKey) ]);
		} else {
			$this->verifyTimestampTolerance($parameters, $credentials);
		}

		$baseString = $isPlaintext
			? ''
			: $this->baseString($httpMethod, $url, $parameters, $oauthConsumerKey);

		if ( ! $this->verifier->verify($baseString, $credentials, $signature) ) {
			$this->fail('Signature does not match', VerificationFailureReason::InvalidSignature, true, $oauthConsumerKey);
		}

		// Only claim the nonce once the signature above is known genuine - see this class's own
		// docblock for why claiming any earlier would be a denial-of-service vector.
		if ( ! $isPlaintext ) {
			$this->claimNonce($parameters, $credentials);
		}

		$this->logger->debug('oauth1.request_verified', [ 'consumer_key' => $this->loggableConsumerKey($oauthConsumerKey) ]);
	}

	/**
	 * Checks presence and tolerance only - claiming the nonce is deliberately deferred to
	 * claimNonce(), called only after the signature is verified. See this class's own docblock.
	 *
	 * @param array<string,string|list<string>> $parameters
	 */
	private function verifyTimestampTolerance( array $parameters, Credentials $credentials ): void {
		$timestamp = $this->requireScalarParameter($parameters, 'oauth_timestamp', $credentials->consumerKey);
		// oauth_nonce's presence is required up front too, even though claiming it is deferred.
		$this->requireScalarParameter($parameters, 'oauth_nonce', $credentials->consumerKey);

		// RFC 5849 §3.3: oauth_timestamp MUST be a positive integer - checked as a canonical
		// decimal string (no sign, no leading zero, no decimal point, no trailing garbage)
		// before it is ever cast to int. PHP's (int) cast silently reads only a value's leading
		// numeric prefix ((int) "137131201garbage" is 137131201, no warning), so without this
		// check a client could send several distinct wire strings that all pass the tolerance
		// check below as "the same" timestamp while each claiming a separate NonceStore entry -
		// NonceStore hashes the raw string, not the cast int - undermining the one-claim-per-
		// nonce guarantee this class exists to provide.
		if ( preg_match('/^[1-9][0-9]*$/', $timestamp) !== 1 ) {
			$this->fail(
				"Timestamp \"$timestamp\" is not a canonical positive integer",
				VerificationFailureReason::MalformedTimestamp,
				false,
				$credentials->consumerKey,
			);
		}

		$age = abs($this->clock->now()->getTimestamp() - (int) $timestamp);
		if ( $age > $this->timestampToleranceSeconds ) {
			$this->fail(
				"Timestamp \"$timestamp\" is outside the {$this->timestampToleranceSeconds}s tolerance",
				VerificationFailureReason::TimestampOutOfWindow,
				false,
				$credentials->consumerKey,
			);
		}
	}

	/**
	 * @param array<string,string|list<string>> $parameters
	 */
	private function claimNonce( array $parameters, Credentials $credentials ): void {
		$timestamp = $this->requireScalarParameter($parameters, 'oauth_timestamp', $credentials->consumerKey);
		$nonce     = $this->requireScalarParameter($parameters, 'oauth_nonce', $credentials->consumerKey);

		// The nonce must stay claimed for exactly as long as this same request would still pass
		// the tolerance check above if replayed - i.e. until now() reaches $timestamp +
		// $timestampToleranceSeconds - not for a flat $timestampToleranceSeconds counted from
		// claim time. A client's clock reading ahead of the server's (ordinary skew, within the
		// tolerance this class already allows) makes those two different: counting from claim
		// time would let the cache entry expire before the request naturally stops being
		// "fresh," leaving a window where a captured, unmodified request - no forged signature
		// needed - replays successfully. Clamped to at least 1 second so a request timestamped
		// at the trailing edge of the tolerance window (age close to the maximum, from the past)
		// does not compute a zero or negative TTL, which PSR-16 leaves implementation-defined.
		$ttlSeconds = max(1, ( (int) $timestamp + $this->timestampToleranceSeconds ) - $this->clock->now()->getTimestamp());

		try {
			$claimed = $this->nonceStore->claim($credentials->consumerKey, $credentials->token, $nonce, $timestamp, $ttlSeconds);
		} catch ( SigningException $exception ) {
			// Rewrapped for the same reason as baseString()'s matching catch block: NonceStore
			// has no Credentials in scope to attach a consumer key to its own exception. A
			// failure to persist the claim is an infrastructure problem, not tampering - thrown
			// rather than returned as `false` so it cannot be conflated with NonceReplayed below
			// and logged as security_relevant: true, the same mistake fixed once already for
			// RsaSha1Verifier's openssl_verify() -1 case.
			$rewrapped = new SigningException($exception->getMessage(), $credentials->consumerKey, $exception);

			$this->logger->error('oauth1.verifying_failed', [
				'consumer_key' => $this->loggableConsumerKey($credentials->consumerKey),
				'exception' => $rewrapped,
				'security_relevant' => false,
			]);

			throw $rewrapped;
		}

		if ( ! $claimed ) {
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
