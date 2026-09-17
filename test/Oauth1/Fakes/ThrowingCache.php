<?php

namespace Oauth1\Fakes;

use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache that throws from has() and/or set(), instead of returning false - the
 * "misbehaving client" case NonceStore::claim() must wrap into a SigningException rather than
 * let propagate raw.
 */
final class ThrowingCache implements CacheInterface {

	public function __construct(
		private readonly bool $throwOnHas = false,
		private readonly bool $throwOnSet = false,
	) {
	}

	public function get( string $key, mixed $default = null ): mixed {
		return $default;
	}

	public function set( string $key, mixed $value, \DateInterval|int|null $ttl = null ): bool {
		if ( $this->throwOnSet ) {
			throw new \RuntimeException('the cache client blew up on set()');
		}

		return true;
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
		return true;
	}

	public function deleteMultiple( iterable $keys ): bool {
		return true;
	}

	public function has( string $key ): bool {
		if ( $this->throwOnHas ) {
			throw new \RuntimeException('the cache client blew up on has()');
		}

		return false;
	}

}
