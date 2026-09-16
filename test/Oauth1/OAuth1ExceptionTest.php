<?php

namespace Oauth1;

use Oauth1\Exceptions\OAuth1Exception;
use PHPUnit\Framework\TestCase;

class OAuth1ExceptionTest extends TestCase {

	public function testGetConsumerKeyReturnsTheConstructedValue(): void {
		$exception = new OAuth1Exception('something failed', consumerKey: 'the-consumer-key');

		$this->assertSame('the-consumer-key', $exception->getConsumerKey());
	}

	public function testGetConsumerKeyDefaultsToNull(): void {
		$exception = new OAuth1Exception('something failed');

		$this->assertNull($exception->getConsumerKey());
	}

	public function testPreviousStillChainsAlongsideConsumerKey(): void {
		$previous  = new \RuntimeException('the underlying cause');
		$exception = new OAuth1Exception('something failed', consumerKey: 'the-consumer-key', previous: $previous);

		$this->assertSame('the-consumer-key', $exception->getConsumerKey());
		$this->assertSame($previous, $exception->getPrevious());
	}

}
