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
 */
final class RequestVerifier {

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
			$this->logger->alert('oauth1.plaintext_method_used', [ 'consumer_key' => $oauthConsumerKey ]);
		} else {
			$this->verifyTimestampAndNonce($parameters, $credentials);
		}

		$baseString = $this->verifier->method() === SignatureMethod::Plaintext
			? ''
			: $this->baseString($httpMethod, $url, $parameters, $oauthConsumerKey);

		if ( ! $this->verifier->verify($baseString, $credentials, $signature) ) {
			$this->fail('Signature does not match', VerificationFailureReason::InvalidSignature, true, $oauthConsumerKey);
		}

		$this->logger->debug('oauth1.request_verified', [ 'consumer_key' => $oauthConsumerKey ]);
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
			return SignatureBaseString::build($httpMethod, $url, $this->withoutSignature($parameters));
		} catch ( SigningException $exception ) {
			$this->logger->error('oauth1.signing_failed', [
				'consumer_key' => $consumerKey,
				'exception' => $exception,
				'security_relevant' => false,
			]);

			throw $exception;
		}
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
			'consumer_key' => $consumerKey,
			'security_relevant' => $securityRelevant,
		]);

		throw new RequestVerificationException($message, $reason);
	}

}
