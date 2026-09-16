<?php

namespace Oauth1;

use PHPUnit\Framework\TestCase;

class CurrentClockTest extends TestCase {

	public function testNowIsCloseToWallClockTime(): void {
		$before = time();
		$now    = (new CurrentClock)->now();
		$after  = time();

		$this->assertGreaterThanOrEqual($before, $now->getTimestamp());
		$this->assertLessThanOrEqual($after, $now->getTimestamp());
	}

}
