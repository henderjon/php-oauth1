<?php

namespace Oauth1;

/**
 * The `oauth_*` protocol parameters RequestSigner produced for one request, including
 * `oauth_signature` - never the request's other, non-OAuth parameters, which the caller already
 * has and is not this class's concern to repeat back.
 */
final class SignedRequest {

	/**
	 * @param array<string,string> $oauthParameters Every `oauth_*` parameter this request
	 *                                               carries, keyed by name, `oauth_signature`
	 *                                               included.
	 */
	public function __construct(
		public readonly array $oauthParameters,
	) {
	}

	/**
	 * RFC 5849 §3.5.1: the OAuth `Authorization` header value, parameters in whatever order this
	 * object holds them, each name and value encoded per §3.6 and quoted.
	 */
	public function authorizationHeaderValue( ?string $realm = null ): string {
		$pairs = $realm !== null ? [ 'realm="' . PercentEncoding::encode($realm) . '"' ] : [];
		foreach ( $this->oauthParameters as $name => $value ) {
			$pairs[] = PercentEncoding::encode($name) . '="' . PercentEncoding::encode($value) . '"';
		}

		return 'OAuth ' . implode(', ', $pairs);
	}

}
