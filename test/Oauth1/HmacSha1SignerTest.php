<?php

namespace Oauth1;

use PHPUnit\Framework\TestCase;

class HmacSha1SignerTest extends TestCase {

	public function testSignMatchesAnIndependentlyVerifiedHmacSha1Computation(): void {
		// The base string is RFC 5849 §3.4.1.1's own worked example (reproduced byte for byte
		// in SignatureBaseStringTest), signed with the client/token secrets §3.1's version of
		// the same example gives. §3.1 also prints an oauth_signature value for this exact
		// input ("bYT5CMsGcbgUdFHObYMEfcx6bsw="), but that value does not actually recompute -
		// a known documentation artifact inherited from the original community spec, not a
		// property of this base string. The expected value below was cross-checked against an
		// independent implementation (Python's hmac/hashlib), not copied from the RFC text.
		$baseString = 'POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3'
			. '%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2'
			. '%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp'
			. '%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7';

		$credentials = new Credentials(
			consumerKey: '9djdj82h48djs9d2',
			consumerSecret: 'j49sk3j29djd',
			token: 'kkk9d7dh3k39sjv7',
			tokenSecret: 'dh893hdasih9',
		);

		$this->assertSame('r6/TJjbCOr97/+UU0NsvSne7s5g=', (new HmacSha1Signer)->sign($baseString, $credentials));
	}

	public function testVerifyAcceptsAMatchingSignature(): void {
		$signer      = new HmacSha1Signer;
		$credentials = new Credentials('key', 'secret');
		$signature   = $signer->sign('base string', $credentials);

		$this->assertTrue($signer->verify('base string', $credentials, $signature));
	}

	public function testVerifyRejectsATamperedBaseString(): void {
		$signer      = new HmacSha1Signer;
		$credentials = new Credentials('key', 'secret');
		$signature   = $signer->sign('base string', $credentials);

		$this->assertFalse($signer->verify('a different base string', $credentials, $signature));
	}

	public function testMethodIsHmacSha1(): void {
		$this->assertSame(SignatureMethod::HmacSha1, (new HmacSha1Signer)->method());
	}

}
