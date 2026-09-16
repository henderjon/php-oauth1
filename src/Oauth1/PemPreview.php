<?php

namespace Oauth1;

/**
 * A summary of an RSA key worth putting in a log record when it could not be read, built only
 * from the PEM format's own fixed boilerplate - never a byte of the key material itself:
 *
 *  - The header line ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----", ...).
 *  - Whether a matching footer line is present anywhere after it.
 *
 * The header alone distinguishes "nothing was passed," "this was never a PEM at all," and "the
 * wrong key type was passed" from each other, but says nothing about the single most common
 * real failure this class exists for: truncation. A key cut off partway through - a copy-paste
 * that missed the last few lines, a value silently capped somewhere in transit - keeps its
 * header fully intact, since that is always the first line; describe() only catches this
 * because it also confirms the corresponding footer actually showed up. Confirmed directly, not
 * assumed: cutting a real key in half here reproduces `openssl_pkey_get_private()` returning
 * `false` while the header line alone reports nothing wrong.
 *
 * Nothing here is a substitute for Redact-style partial reveal of a value derived from a secret;
 * there is nothing here derived from a secret to partially reveal - it only ever reports on the
 * two boilerplate lines the PEM format itself defines.
 */
final class PemPreview {

	public static function describe( string $pem ): string {
		$firstLine = trim(explode("\n", $pem, 2)[0]);

		if ( $firstLine === '' ) {
			return '(empty)';
		}

		if ( preg_match('/^-----BEGIN ([A-Z0-9 ]+)-----$/', $firstLine, $match ) !== 1 ) {
			return '(no PEM header found)';
		}

		$hasFooter = preg_match('/^-----END ' . preg_quote($match[1], '/') . '-----$/m', $pem) === 1;

		return $hasFooter ? $firstLine : "$firstLine (footer missing - likely truncated)";
	}

}
