<?php

namespace BasicLti1;

use BasicLti1\Exceptions\InvalidLaunchException;
use PHPUnit\Framework\TestCase;

class InvalidLaunchExceptionTest extends TestCase {

	public function testGetReasonReturnsTheReasonItWasConstructedWith(): void {
		$exception = new InvalidLaunchException('missing resource_link_id', LaunchValidationFailureReason::MissingResourceLinkId);

		$this->assertSame(LaunchValidationFailureReason::MissingResourceLinkId, $exception->getReason());
		$this->assertSame('missing resource_link_id', $exception->getMessage());
	}

	public function testGetConsumerKeyIsInheritedFromTheBaseException(): void {
		$exception = new InvalidLaunchException('missing resource_link_id', LaunchValidationFailureReason::MissingResourceLinkId, 'the-consumer-key');

		$this->assertSame('the-consumer-key', $exception->getConsumerKey());
	}

	public function testPreviousIsInheritedFromTheBaseException(): void {
		$previous  = new \RuntimeException('underlying failure');
		$exception = new InvalidLaunchException('missing resource_link_id', LaunchValidationFailureReason::MissingResourceLinkId, 'the-consumer-key', $previous);

		$this->assertSame($previous, $exception->getPrevious());
	}

}
