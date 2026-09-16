<?php

namespace Oauth1\Fakes;

use Psr\Clock\ClockInterface;

final class FixedClock implements ClockInterface {

	public function __construct(
		private readonly \DateTimeImmutable $now,
	) {
	}

	public function now(): \DateTimeImmutable {
		return $this->now;
	}

}
