<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Oauth1\Fakes\FailingWriteCache;
use Oauth1\Fakes\InMemoryCache;
use Oauth1\Fakes\ThrowingCache;
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

	/**
	 * A cache client that throws instead of returning false must not propagate raw - it is
	 * wrapped into this library's own exception type, per AGENTS.md's rule for external calls,
	 * and stays distinguishable from an ordinary write-failure via getPrevious().
	 */
	public function testClaimWrapsAnExceptionTheCacheThrowsWhileChecking(): void {
		$store = new NonceStore(new ThrowingCache(throwOnHas: true));

		try {
			$store->claim('consumer', 'token', 'nonce', '137131201', 300);
			$this->fail('Expected a SigningException');
		} catch ( SigningException $exception ) {
			$this->assertInstanceOf(\RuntimeException::class, $exception->getPrevious());
		}
	}

	public function testClaimWrapsAnExceptionTheCacheThrowsWhilePersisting(): void {
		$store = new NonceStore(new ThrowingCache(throwOnSet: true));

		try {
			$store->claim('consumer', 'token', 'nonce', '137131201', 300);
			$this->fail('Expected a SigningException');
		} catch ( SigningException $exception ) {
			$this->assertInstanceOf(\RuntimeException::class, $exception->getPrevious());
		}
	}

}
