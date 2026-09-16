<?php

namespace Oauth1;

/**
 * RFC 5849 §3.6's percent-encoding: RFC 3986's unreserved set (ALPHA, DIGIT, "-", ".", "_", "~")
 * left unescaped, uppercase hex for everything else - exactly what PHP's rawurlencode() has done
 * since PHP 5.3. Deliberately not urlencode(): that encodes space as "+" instead of "%20", which
 * would build a signature base string a spec-compliant implementation on the other side could
 * never reproduce.
 */
final class PercentEncoding {

	public static function encode( string $value ): string {
		return rawurlencode($value);
	}

}
