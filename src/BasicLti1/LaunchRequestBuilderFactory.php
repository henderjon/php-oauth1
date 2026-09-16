<?php

namespace BasicLti1;

use Oauth1\RequestSignerFactory;
use Oauth1\SignatureMethod;

/**
 * Assembles a LaunchRequestBuilder wired to HMAC-SHA1 - the Basic LTI Implementation Guide's own
 * words: "TC and TP must support and use the HMAC-SHA1 signing method" - so a caller building
 * launches never reaches for `new` on LaunchRequestBuilder, RequestSigner, or HmacSha1Signer
 * itself, and never has an opportunity to wire up a signature method Basic LTI does not allow.
 */
final class LaunchRequestBuilderFactory {

	public function __construct(
		private readonly RequestSignerFactory $signerFactory = new RequestSignerFactory,
	) {
	}

	public function make(): LaunchRequestBuilder {
		return new LaunchRequestBuilder($this->signerFactory->forMethod(SignatureMethod::HmacSha1));
	}

}
