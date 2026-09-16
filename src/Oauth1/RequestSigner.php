<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Signs one outgoing request: assembles the `oauth_*` protocol parameters RFC 5849 §3.1
 * requires, builds the signature base string (§3.4.1) for HMAC-SHA1/RSA-SHA1, and delegates the
 * signature itself to the injected SignerInterface - so choosing HMAC-SHA1, RSA-SHA1, or
 * PLAINTEXT is a constructor argument, never a branch in this class.
 *
 * `oauth_timestamp` and `oauth_nonce` are omitted for PLAINTEXT, per §3.1 and §3.4.4 - PLAINTEXT
 * uses neither, so including them would only be dead weight on the wire. Every PLAINTEXT sign()
 * call also logs an `alert` - PLAINTEXT "MUST only be used over TLS" (§3.4.4), a configuration
 * choice worth a developer's own review, and this class has no way to enforce it. Logged every
 * time, not once, since every request made this way is unauthenticated if TLS is not actually in
 * place - mirroring Oidc\CurlHttpFetcher's own TLS-disabled alert.
 */
final class RequestSigner {

	public function __construct(
		private readonly SignerInterface $signer,
		private readonly NonceGeneratorInterface $nonceGenerator = new RandomNonceGenerator,
		private readonly ClockInterface $clock = new CurrentClock,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @param array<string,string|list<string>> $requestParameters Non-OAuth parameters this
	 *                                                              request also carries (query
	 *                                                              string and/or form body) -
	 *                                                              included in the signature base
	 *                                                              string per RFC 5849
	 *                                                              §3.4.1.3.1, but never
	 *                                                              returned; the caller already
	 *                                                              has them.
	 * @param ?string $callback `oauth_callback`, for a Temporary Credential Request (RFC 5849
	 *                          §2.1) - omitted entirely otherwise, since it has no meaning on any
	 *                          other request.
	 */
	public function sign(
		string $httpMethod,
		string $url,
		Credentials $credentials,
		array $requestParameters = [],
		?string $callback = null,
	): SignedRequest {
		$oauthParameters = [
			'oauth_consumer_key' => $credentials->consumerKey,
			'oauth_signature_method' => $this->signer->method()->value,
		];

		if ( $credentials->token !== '' ) {
			$oauthParameters['oauth_token'] = $credentials->token;
		}

		if ( $callback !== null ) {
			$oauthParameters['oauth_callback'] = $callback;
		}

		if ( $this->signer->method() === SignatureMethod::Plaintext ) {
			$this->logger->alert('oauth1.plaintext_method_used', [ 'consumer_key' => $credentials->consumerKey ]);
		} else {
			$oauthParameters['oauth_timestamp'] = (string) $this->clock->now()->getTimestamp();
			$oauthParameters['oauth_nonce']     = $this->nonceGenerator->generate();
		}

		$oauthParameters['oauth_version'] = '1.0';

		$baseString = $this->signer->method() === SignatureMethod::Plaintext ? '' : $this->baseString($httpMethod, $url, $requestParameters, $oauthParameters, $credentials);

		$oauthParameters['oauth_signature'] = $this->signer->sign($baseString, $credentials);

		$this->logger->debug('oauth1.request_signed', [
			'consumer_key' => $credentials->consumerKey,
			'signature_method' => $this->signer->method()->value,
		]);

		return new SignedRequest($oauthParameters);
	}

	/**
	 * @param array<string,string|list<string>> $requestParameters
	 * @param array<string,string>              $oauthParameters
	 */
	private function baseString( string $httpMethod, string $url, array $requestParameters, array $oauthParameters, Credentials $credentials ): string {
		try {
			return SignatureBaseString::build($httpMethod, $url, [ ...$requestParameters, ...$oauthParameters ]);
		} catch ( SigningException $exception ) {
			$this->logger->error('oauth1.signing_failed', [
				'consumer_key' => $credentials->consumerKey,
				'exception' => $exception,
				'security_relevant' => false,
			]);

			throw $exception;
		}
	}

}
