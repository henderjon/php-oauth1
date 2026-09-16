<?php

namespace Oauth1\Exceptions;

/**
 * Thrown when a signer or verifier cannot even attempt a signature - a malformed URL with no
 * scheme or host to build a base string URI from, an unreadable RSA key, or openssl itself
 * rejecting the input. Never thrown for a signature that was computed and simply did not match -
 * that is RequestVerificationException's job.
 */
class SigningException extends OAuth1Exception {

}
