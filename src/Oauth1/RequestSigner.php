<?php

namespace Oauth1;

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
 * uses neither, so including them would only be dead weight on the wire.
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

		if ( $this->signer->method() !== SignatureMethod::Plaintext ) {
			$oauthParameters['oauth_timestamp'] = (string) $this->clock->now()->getTimestamp();
			$oauthParameters['oauth_nonce']     = $this->nonceGenerator->generate();
		}

		$oauthParameters['oauth_version'] = '1.0';

		$baseString = $this->signer->method() === SignatureMethod::Plaintext
			? ''
			: SignatureBaseString::build($httpMethod, $url, [ ...$requestParameters, ...$oauthParameters ]);

		$oauthParameters['oauth_signature'] = $this->signer->sign($baseString, $credentials);

		$this->logger->debug('oauth1.request_signed', [
			'consumer_key' => $credentials->consumerKey,
			'signature_method' => $this->signer->method()->value,
		]);

		return new SignedRequest($oauthParameters);
	}

}
