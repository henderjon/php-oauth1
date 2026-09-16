<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;

/**
 * Builds the RFC 5849 §3.4.1 signature base string: the HTTP method, the base string URI
 * (§3.4.1.2 - scheme+host+path, lowercased, default port dropped, no query or fragment), and the
 * merged, sorted, percent-encoded request parameters (§3.4.1.3), joined by "&". HMAC-SHA1 and
 * RSA-SHA1 sign this string directly; PLAINTEXT never calls this class at all.
 *
 * Callers are responsible for merging parameters from every source RFC 5849 §3.4.1.3.1 lists
 * (the URI query, the OAuth `Authorization` header minus `realm`, and a form-encoded body) into
 * the flat `$parameters` list before calling build() - this class only normalizes and encodes
 * what it is given. `oauth_signature` itself, and `realm`, must already be excluded.
 */
final class SignatureBaseString {

	/**
	 * @param string                             $url        The full request URI, query string
	 *                                                        included if it has one - only the
	 *                                                        scheme, host, port, and path are
	 *                                                        used (§3.4.1.2); any query is
	 *                                                        expected separately in `$parameters`.
	 * @param array<string,string|list<string>>  $parameters Decoded parameter values, keyed by
	 *                                                        decoded name. A repeated parameter
	 *                                                        name (e.g. two "a3" values) is a
	 *                                                        list, not a scalar.
	 */
	public static function build( string $httpMethod, string $url, array $parameters ): string {
		return implode('&', [
			strtoupper($httpMethod),
			PercentEncoding::encode(self::baseStringUri($url)),
			PercentEncoding::encode(self::normalizeParameters($parameters)),
		]);
	}

	/**
	 * RFC 5849 §3.4.1.2: scheme and host lowercased, default port (80 for "http", 443 for
	 * "https") dropped, every other port kept, query and fragment dropped entirely.
	 */
	private static function baseStringUri( string $url ): string {
		$parts = parse_url($url);
		if ( $parts === false || ! isset($parts['scheme'], $parts['host']) ) {
			// Deliberately does not interpolate $url into the message - it is caller/attacker
			// data of unbounded length (RequestVerifier's caller passes it straight from an
			// incoming, not-yet-validated request), and this exception's message ends up in a
			// log line via RequestSigner/RequestVerifier's own catch blocks, unlike
			// oauth_consumer_key, which those same log lines explicitly cap before logging. The
			// caller catching this already has the offending $url in scope - it is the same
			// argument they passed into sign()/verify() - so nothing is lost by leaving it out.
			throw new SigningException('URL has no scheme or host to build a base string URI from');
		}

		$scheme = strtolower($parts['scheme']);
		$host   = strtolower($parts['host']);
		$path   = $parts['path'] ?? '/';

		$defaultPort = match ( $scheme ) {
			'http'  => 80,
			'https' => 443,
			default => null,
		};
		$port = isset($parts['port']) && $parts['port'] !== $defaultPort ? ':' . $parts['port'] : '';

		return "{$scheme}://{$host}{$port}{$path}";
	}

	/**
	 * RFC 5849 §3.4.1.3.2: encode every name and value, sort by encoded name (then encoded
	 * value, for a repeated name), and concatenate as "name=value" pairs joined by "&".
	 *
	 * @param array<string,string|list<string>> $parameters
	 */
	private static function normalizeParameters( array $parameters ): string {
		$pairs = [];
		foreach ( $parameters as $name => $value ) {
			$encodedName = PercentEncoding::encode((string) $name);
			foreach ( is_array($value) ? $value : [ $value ] as $oneValue ) {
				$pairs[] = [ $encodedName, PercentEncoding::encode($oneValue) ];
			}
		}

		usort($pairs, fn ( array $a, array $b ) => $a[0] <=> $b[0] ?: $a[1] <=> $b[1]);

		return implode('&', array_map(fn ( array $pair ) => "{$pair[0]}={$pair[1]}", $pairs));
	}

}
