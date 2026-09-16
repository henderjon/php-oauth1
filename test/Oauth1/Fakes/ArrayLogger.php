<?php

namespace Oauth1\Fakes;

use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;

/**
 * A PSR-3 logger that records every call instead of writing anywhere, so tests can assert on
 * what the library chose to log without a real logging backend.
 */
final class ArrayLogger extends AbstractLogger {

	/** @var list<array{level: mixed, message: string, context: array<string,mixed>}> */
	public array $records = [];

	public function log( $level, string|\Stringable $message, array $context = [] ): void {
		$this->records[] = [ 'level' => $level, 'message' => (string) $message, 'context' => $context ];
	}

	/**
	 * @return list<array{level: mixed, message: string, context: array<string,mixed>}>
	 */
	public function recordsAt( string $level ): array {
		return array_values(array_filter($this->records, static fn ( array $record ): bool => $record['level'] === $level));
	}

	/**
	 * @return list<array{level: mixed, message: string, context: array<string,mixed>}>
	 */
	public function recordsAboveDebug(): array {
		return array_values(array_filter($this->records, static fn ( array $record ): bool => $record['level'] !== LogLevel::DEBUG));
	}

}
