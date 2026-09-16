<?php

namespace Oauth1\Fakes;

use Oauth1\NonceGeneratorInterface;

final class FixedNonceGenerator implements NonceGeneratorInterface {

	public function __construct(
		private readonly string $nonce,
	) {
	}

	public function generate(): string {
		return $this->nonce;
	}

}
