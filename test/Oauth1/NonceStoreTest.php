<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Oauth1\Fakes\FailingWriteCache;
use Oauth1\Fakes\InMemoryCache;
use PHPUnit\Framework\TestCase;

class NonceStoreTest extends TestCase {

	public function testClaimSucceedsTheFirstTimeAndFailsOnReplay(): void {
		$store = new NonceStore(new InMemoryCache);

		$this->assertTrue($store->claim('consumer', 'token', 'nonce', '137131201', 300));
		$this->assertFalse($store->claim('consumer', 'token', 'nonce', '137131201', 300));
	}

	public function testClaimTreatsADifferentNonceAsUnrelated(): void {
		$store = new NonceStore(new InMemoryCache);

		$this->assertTrue($store->claim('consumer', 'token', 'nonce-one', '137131201', 300));
		$this->assertTrue($store->claim('consumer', 'token', 'nonce-two', '137131201', 300));
	}

	public function testCacheKeySuffixKeepsTwoStoresIndependent(): void {
		$cache  = new InMemoryCache;
		$storeA = new NonceStore($cache, ':a');
		$storeB = new NonceStore($cache, ':b');

		$this->assertTrue($storeA->claim('consumer', 'token', 'nonce', '137131201', 300));
		$this->assertTrue($storeB->claim('consumer', 'token', 'nonce', '137131201', 300));
	}

	/**
	 * A cache that honestly reports a write failure must not be treated the same as a
	 * successful claim - that would silently disable replay protection during cache trouble,
	 * the opposite of this class's own fail-closed purpose.
	 */
	public function testClaimThrowsRatherThanReturningTrueWhenTheCacheWriteFails(): void {
		$store = new NonceStore(new FailingWriteCache);

		$this->expectException(SigningException::class);

		$store->claim('consumer', 'token', 'nonce', '137131201', 300);
	}

}
