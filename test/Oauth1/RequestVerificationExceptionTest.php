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

	public function testGetConsumerKeyIsInheritedFromTheBaseException(): void {
		$exception = new RequestVerificationException('nonce replayed', VerificationFailureReason::NonceReplayed, 'the-consumer-key');

		$this->assertSame('the-consumer-key', $exception->getConsumerKey());
	}

	public function testGetBaseStringSha256IsInheritedFromTheBaseException(): void {
		$exception = new RequestVerificationException(
			'signature does not match',
			VerificationFailureReason::InvalidSignature,
			baseStringSha256: 'deadbeef',
		);

		$this->assertSame('deadbeef', $exception->getBaseStringSha256());
	}

}
