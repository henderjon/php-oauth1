<?php

namespace Oauth1;

/**
 * The three signature methods RFC 5849 §3.4 defines. Backed by the exact string each puts in
 * the `oauth_signature_method` protocol parameter.
 */
enum SignatureMethod: string {

	case HmacSha1 = 'HMAC-SHA1';
	case RsaSha1 = 'RSA-SHA1';
	case Plaintext = 'PLAINTEXT';

}
