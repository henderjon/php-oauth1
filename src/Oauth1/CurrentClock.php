<?php

namespace Oauth1;

use Psr\Clock\ClockInterface;

/**
 * The production ClockInterface: wall-clock time, for `oauth_timestamp` and for
 * RequestVerifier's timestamp-window check.
 */
final class CurrentClock implements ClockInterface {

	public function now(): \DateTimeImmutable {
		return new \DateTimeImmutable();
	}

}
