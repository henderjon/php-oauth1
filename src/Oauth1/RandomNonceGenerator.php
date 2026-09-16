<?php

namespace Oauth1;

/**
 * The production NonceGeneratorInterface: a random hex string long enough that a collision
 * within the same timestamp is not a practical concern.
 */
final class RandomNonceGenerator implements NonceGeneratorInterface {

	public function generate(): string {
		return bin2hex(random_bytes(16));
	}

}
