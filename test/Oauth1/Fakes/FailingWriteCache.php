<?php

namespace Oauth1\Fakes;

use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache that honestly reports every write as failed - the case NonceStore::claim() must
 * not conflate with a successful claim. has() always reports nothing claimed yet, so claim()
 * always reaches the set() call this exists to fail.
 */
final class FailingWriteCache implements CacheInterface {

	public function get( string $key, mixed $default = null ): mixed {
		return $default;
	}

	public function set( string $key, mixed $value, \DateInterval|int|null $ttl = null ): bool {
		return false;
	}

	public function delete( string $key ): bool {
		return true;
	}

	public function clear(): bool {
		return true;
	}

	public function getMultiple( iterable $keys, mixed $default = null ): iterable {
		foreach ( $keys as $key ) {
			yield $key => $default;
		}
	}

	public function setMultiple( iterable $values, \DateInterval|int|null $ttl = null ): bool {
		return false;
	}

	public function deleteMultiple( iterable $keys ): bool {
		return true;
	}

	public function has( string $key ): bool {
		return false;
	}

}
