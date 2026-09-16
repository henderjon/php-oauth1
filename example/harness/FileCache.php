<?php

namespace Harness;

use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache backed by a JSON file on disk - what NonceStore needs to actually catch a
 * replayed launch here. php's built-in dev server starts a fresh process for every request, so
 * an in-memory cache would forget every nonce the instant the request that recorded it ended;
 * this stands in for whatever durable cache (Redis, Memcached, a database table) a real Tool
 * Provider would use instead.
 *
 * Read-modify-write, not safe under real concurrency - fine for one developer clicking buttons
 * in a browser, not a pattern to copy for anything that takes real traffic.
 */
final class FileCache implements CacheInterface {

	public function __construct(
		private readonly string $path,
	) {
	}

	public function get( string $key, mixed $default = null ): mixed {
		$entry = $this->read()[$key] ?? null;

		if ( ! is_array($entry) || ! array_key_exists('value', $entry) ) {
			return $default;
		}

		if ( $entry['expires_at'] !== null && $entry['expires_at'] < time() ) {
			return $default;
		}

		return $entry['value'];
	}

	public function set( string $key, mixed $value, \DateInterval|int|null $ttl = null ): bool {
		$data = $this->read();
		$data[$key] = [ 'value' => $value, 'expires_at' => $this->expiresAt($ttl) ];
		$this->write($data);

		return true;
	}

	public function delete( string $key ): bool {
		$data = $this->read();
		unset($data[$key]);
		$this->write($data);

		return true;
	}

	public function clear(): bool {
		$this->write([]);

		return true;
	}

	/**
	 * @param iterable<string> $keys
	 * @return iterable<string,mixed>
	 */
	public function getMultiple( iterable $keys, mixed $default = null ): iterable {
		foreach ( $keys as $key ) {
			yield $key => $this->get($key, $default);
		}
	}

	/**
	 * @param iterable<string,mixed> $values
	 */
	public function setMultiple( iterable $values, \DateInterval|int|null $ttl = null ): bool {
		foreach ( $values as $key => $value ) {
			$this->set((string) $key, $value, $ttl);
		}

		return true;
	}

	/**
	 * @param iterable<string> $keys
	 */
	public function deleteMultiple( iterable $keys ): bool {
		foreach ( $keys as $key ) {
			$this->delete($key);
		}

		return true;
	}

	public function has( string $key ): bool {
		$miss = new \stdClass;

		return $this->get($key, $miss) !== $miss;
	}

	/**
	 * @return array<string,array{value:mixed,expires_at:?int}>
	 */
	private function read(): array {
		if ( ! is_file($this->path) ) {
			return [];
		}

		$decoded = json_decode((string) file_get_contents($this->path), true);

		return is_array($decoded) ? $decoded : [];
	}

	/**
	 * @param array<string,array{value:mixed,expires_at:?int}> $data
	 */
	private function write( array $data ): void {
		if ( ! is_dir(dirname($this->path)) ) {
			mkdir(dirname($this->path), 0777, true);
		}

		file_put_contents($this->path, json_encode($data));
	}

	private function expiresAt( \DateInterval|int|null $ttl ): ?int {
		if ( $ttl === null ) {
			return null;
		}

		if ( is_int($ttl) ) {
			return time() + $ttl;
		}

		return (new \DateTimeImmutable())->add($ttl)->getTimestamp();
	}

}
