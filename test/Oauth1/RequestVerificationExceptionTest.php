<?php

namespace Oauth1;

use Oauth1\Exceptions\RequestVerificationException;
use PHPUnit\Framework\TestCase;

class RequestVerificationExceptionTest extends TestCase {

	public function testGetReasonReturnsTheReasonItWasConstructedWith(): void {
		$exception = new RequestVerificationException('nonce replayed', VerificationFailureReason::NonceReplayed);

		$this->assertSame(VerificationFailureReason::NonceReplayed, $exception->getReason());
		$this->assertSame('nonce replayed', $exception->getMessage());
	}

}
