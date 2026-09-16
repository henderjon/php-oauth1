<?php

namespace Oauth1;

/**
 * The identifiers OAuth 1.0 attaches to a request: the consumer key and, once a token has been
 * issued, the token identifier. This does not carry RSA key material - RFC 5849 §3.4.1 itself
 * draws that line, noting RSA-SHA1 "does not use the token shared-secret, or any provisioned
 * client shared-secret" at all. See RsaSha1Signer/RsaSha1Verifier for where a key pair lives
 * instead.
 *
 * A Basic LTI launch (one-legged: no token exchange) simply never sets `token`/`tokenSecret`.
 */
final class Credentials {

	public function __construct(
		public readonly string $consumerKey,
		public readonly string $consumerSecret = '',
		public readonly string $token = '',
		public readonly string $tokenSecret = '',
	) {
	}

	public function withConsumerKey( string $consumerKey ): self {
		return new self($consumerKey, $this->consumerSecret, $this->token, $this->tokenSecret);
	}

	public function withConsumerSecret( string $consumerSecret ): self {
		return new self($this->consumerKey, $consumerSecret, $this->token, $this->tokenSecret);
	}

	public function withToken( string $token ): self {
		return new self($this->consumerKey, $this->consumerSecret, $token, $this->tokenSecret);
	}

	public function withTokenSecret( string $tokenSecret ): self {
		return new self($this->consumerKey, $this->consumerSecret, $this->token, $tokenSecret);
	}

}
