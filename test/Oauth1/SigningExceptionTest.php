<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use PHPUnit\Framework\TestCase;

class SigningExceptionTest extends TestCase {

	public function testGetConsumerKeyStillChainsThroughToTheBaseException(): void {
		$exception = new SigningException('key could not be read', 'the-consumer-key');

		$this->assertSame('the-consumer-key', $exception->getConsumerKey());
	}

	public function testPreviousStillChainsAlongsideConsumerKey(): void {
		$previous  = new \RuntimeException('the underlying cause');
		$exception = new SigningException('key could not be read', 'the-consumer-key', $previous);

		$this->assertSame($previous, $exception->getPrevious());
	}

	public function testGetBaseStringSha256ReturnsTheConstructedValue(): void {
		$exception = new SigningException('nonce store write failed', 'the-consumer-key', baseStringSha256: 'deadbeef');

		$this->assertSame('deadbeef', $exception->getBaseStringSha256());
	}

	public function testGetBaseStringSha256DefaultsToNull(): void {
		$exception = new SigningException('a malformed URL was passed');

		$this->assertNull($exception->getBaseStringSha256());
	}

}
