<?php

namespace Oauth1;

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

}
