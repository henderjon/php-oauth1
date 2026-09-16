<?php

namespace Oauth1\Fakes;

use Psr\SimpleCache\CacheInterface;

/**
 * A real, in-memory PSR-16 cache for tests - not a mock, so NonceStore's actual get-then-set
 * logic runs for real against it.
 */
final class InMemoryCache implements CacheInterface {

	/** @var array<string,mixed> */
	private array $values = [];

	public function get( string $key, mixed $default = null ): mixed {
		return $this->values[$key] ?? $default;
	}

	public function set( string $key, mixed $value, \DateInterval|int|null $ttl = null ): bool {
		$this->values[$key] = $value;

		return true;
	}

	public function delete( string $key ): bool {
		unset($this->values[$key]);

		return true;
	}

	public function clear(): bool {
		$this->values = [];

		return true;
	}

	public function getMultiple( iterable $keys, mixed $default = null ): iterable {
		foreach ( $keys as $key ) {
			yield $key => $this->get($key, $default);
		}
	}

	public function setMultiple( iterable $values, \DateInterval|int|null $ttl = null ): bool {
		foreach ( $values as $key => $value ) {
			$this->set($key, $value, $ttl);
		}

		return true;
	}

	public function deleteMultiple( iterable $keys ): bool {
		foreach ( $keys as $key ) {
			$this->delete($key);
		}

		return true;
	}

	public function has( string $key ): bool {
		return array_key_exists($key, $this->values);
	}

}
