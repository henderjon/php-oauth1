<?php

namespace BasicLti1;

use BasicLti1\Exceptions\BasicLti1Exception;
use PHPUnit\Framework\TestCase;

class BasicLti1ExceptionTest extends TestCase {

	public function testGetConsumerKeyReturnsTheConstructedValue(): void {
		$exception = new BasicLti1Exception('something failed', consumerKey: 'the-consumer-key');

		$this->assertSame('the-consumer-key', $exception->getConsumerKey());
	}

	public function testGetConsumerKeyDefaultsToNull(): void {
		$exception = new BasicLti1Exception('something failed');

		$this->assertNull($exception->getConsumerKey());
	}

	public function testPreviousStillChainsAlongsideConsumerKey(): void {
		$previous  = new \RuntimeException('the underlying cause');
		$exception = new BasicLti1Exception('something failed', consumerKey: 'the-consumer-key', previous: $previous);

		$this->assertSame('the-consumer-key', $exception->getConsumerKey());
		$this->assertSame($previous, $exception->getPrevious());
	}

}
