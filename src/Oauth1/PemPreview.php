<?php

namespace Oauth1;

/**
 * The one line of an RSA key worth putting in a log record when it could not be read: its PEM
 * header ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----", ...). That header is
 * fixed boilerplate defined by the PEM format itself, never derived from the key's own bytes, so
 * it distinguishes "the wrong key type was passed," "nothing was passed," and "this was never a
 * PEM at all" from each other without exposing a single byte of the key material that follows
 * it. Nothing here is a substitute for Redact-style partial reveal of a value derived from a
 * secret; there is nothing here derived from a secret to partially reveal - it either finds
 * that boilerplate line or it does not.
 */
final class PemPreview {

	public static function headerLine( string $pem ): string {
		$firstLine = trim(explode("\n", $pem, 2)[0]);

		if ( $firstLine === '' ) {
			return '(empty)';
		}

		return preg_match('/^-----BEGIN [A-Z0-9 ]+-----$/', $firstLine) === 1
			? $firstLine
			: '(no PEM header found)';
	}

}
