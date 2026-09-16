<?php

namespace Oauth1;

/**
 * Why RequestVerifier rejected a request - attached to
 * Exceptions\RequestVerificationException so a caller can log or respond differently for, say, a
 * replayed nonce versus an unknown consumer key, without parsing the exception message.
 */
enum VerificationFailureReason {

	case MissingParameter;
	case UnsupportedVersion;
	case UnsupportedSignatureMethod;
	case ConsumerKeyMismatch;
	case TimestampOutOfWindow;
	case NonceReplayed;
	case InvalidSignature;

}
