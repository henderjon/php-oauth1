<?php

namespace Oauth1;

use Oauth1\Exceptions\RequestVerificationException;
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
 * so a caller cannot accidentally treat "did not check" the same as "checked and passed".
 *
 * `$credentials` must already carry the consumer secret (and token secret, if any) the caller
 * looked up for the incoming `oauth_consumer_key` - this class does not know how or where that
 * lookup happens, the same way Oidc's collaborators never look up a client's own registration
 * themselves.
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
		$oauthConsumerKey = $this->requireScalarParameter($parameters, 'oauth_consumer_key');
		$signatureMethod  = $this->requireScalarParameter($parameters, 'oauth_signature_method');
		$signature        = $this->requireScalarParameter($parameters, 'oauth_signature');

		$oauthVersion = $parameters['oauth_version'] ?? '1.0';
		if ( $oauthVersion !== '1.0' ) {
			$shown = is_string($oauthVersion) ? $oauthVersion : 'a repeated parameter';
			throw new RequestVerificationException(
				"Unsupported oauth_version \"$shown\"",
				VerificationFailureReason::UnsupportedVersion,
			);
		}

		if ( $signatureMethod !== $this->verifier->method()->value ) {
			throw new RequestVerificationException(
				"Request signed with \"$signatureMethod\", this verifier only accepts \"{$this->verifier->method()->value}\"",
				VerificationFailureReason::UnsupportedSignatureMethod,
			);
		}

		if ( $oauthConsumerKey !== $credentials->consumerKey ) {
			throw new RequestVerificationException(
				'oauth_consumer_key does not match the credentials looked up for this request',
				VerificationFailureReason::ConsumerKeyMismatch,
			);
		}

		if ( $this->verifier->method() !== SignatureMethod::Plaintext ) {
			$this->verifyTimestampAndNonce($parameters, $credentials);
		}

		$baseString = $this->verifier->method() === SignatureMethod::Plaintext
			? ''
			: SignatureBaseString::build($httpMethod, $url, $this->withoutSignature($parameters));

		if ( ! $this->verifier->verify($baseString, $credentials, $signature) ) {
			$this->logger->warning('oauth1.signature_mismatch', [ 'consumer_key' => $oauthConsumerKey ]);

			throw new RequestVerificationException('Signature does not match', VerificationFailureReason::InvalidSignature);
		}

		$this->logger->debug('oauth1.request_verified', [ 'consumer_key' => $oauthConsumerKey ]);
	}

	/**
	 * @param array<string,string|list<string>> $parameters
	 */
	private function verifyTimestampAndNonce( array $parameters, Credentials $credentials ): void {
		$timestamp = $this->requireScalarParameter($parameters, 'oauth_timestamp');
		$nonce     = $this->requireScalarParameter($parameters, 'oauth_nonce');

		$age = abs($this->clock->now()->getTimestamp() - (int) $timestamp);
		if ( $age > $this->timestampToleranceSeconds ) {
			throw new RequestVerificationException(
				"Timestamp \"$timestamp\" is outside the {$this->timestampToleranceSeconds}s tolerance",
				VerificationFailureReason::TimestampOutOfWindow,
			);
		}

		if ( ! $this->nonceStore->claim($credentials->consumerKey, $credentials->token, $nonce, $timestamp, $this->timestampToleranceSeconds) ) {
			throw new RequestVerificationException('Nonce has already been used', VerificationFailureReason::NonceReplayed);
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
	private function requireScalarParameter( array $parameters, string $name ): string {
		$value = $parameters[$name] ?? null;
		if ( ! is_string($value) || $value === '' ) {
			throw new RequestVerificationException("Missing required parameter \"$name\"", VerificationFailureReason::MissingParameter);
		}

		return $value;
	}

}
