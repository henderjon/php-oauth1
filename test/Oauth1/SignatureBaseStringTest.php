<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use PHPUnit\Framework\TestCase;

class SignatureBaseStringTest extends TestCase {

	public function testBuildMatchesTheRfc5849WorkedExample(): void {
		// RFC 5849 §3.4.1.1's own worked example, reproduced byte for byte.
		$parameters = [
			'b5' => '=%3D',
			'a3' => [ 'a', '2 q' ],
			'c@' => '',
			'a2' => 'r b',
			'c2' => '',
			'oauth_consumer_key' => '9djdj82h48djs9d2',
			'oauth_token' => 'kkk9d7dh3k39sjv7',
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_timestamp' => '137131201',
			'oauth_nonce' => '7d8f3e4a',
		];

		$baseString = SignatureBaseString::build(
			'POST',
			'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b',
			$parameters,
		);

		$this->assertSame(
			'POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5'
			. '%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_'
			. 'nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201'
			. '%26oauth_token%3Dkkk9d7dh3k39sjv7',
			$baseString,
		);
	}

	public function testBuildDropsTheDefaultHttpPort(): void {
		// RFC 5849 §3.4.1.2's own example.
		$baseString = SignatureBaseString::build('GET', 'http://EXAMPLE.COM:80/r%20v/X?id=123', []);

		$this->assertStringContainsString(PercentEncoding::encode('http://example.com/r%20v/X'), $baseString);
	}

	public function testBuildKeepsANonDefaultPort(): void {
		// RFC 5849 §3.4.1.2's own example.
		$baseString = SignatureBaseString::build('GET', 'https://www.example.net:8080/?q=1', []);

		$this->assertStringContainsString(PercentEncoding::encode('https://www.example.net:8080/'), $baseString);
	}

	public function testBuildThrowsForAUrlWithNoHost(): void {
		$this->expectException(SigningException::class);

		SignatureBaseString::build('GET', '/relative/path', []);
	}

}
