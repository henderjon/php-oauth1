<?php

namespace Oauth1;

use Oauth1\Fakes\FixedClock;
use Oauth1\Fakes\FixedNonceGenerator;
use PHPUnit\Framework\TestCase;

class RequestSignerTest extends TestCase {

	private function signer(): RequestSigner {
		return new RequestSigner(
			new HmacSha1Signer,
			new FixedNonceGenerator('7d8f3e4a'),
			new FixedClock(new \DateTimeImmutable('@137131201')),
		);
	}

	public function testSignReproducesTheRfc5849WorkedExampleParameters(): void {
		// Same worked example as HmacSha1SignerTest, but through RequestSigner, which always
		// adds oauth_version (optional per RFC 5849 §3.1, and absent from that section's own
		// example) - so the expected signature here differs from HmacSha1SignerTest's, and is
		// independently-verified (Python's hmac/hashlib) against the base string including
		// oauth_version, not copied from the RFC text.
		$credentials = new Credentials(
			consumerKey: '9djdj82h48djs9d2',
			consumerSecret: 'j49sk3j29djd',
			token: 'kkk9d7dh3k39sjv7',
			tokenSecret: 'dh893hdasih9',
		);

		$signed = $this->signer()->sign(
			'POST',
			'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b',
			$credentials,
			[
				'b5' => '=%3D',
				'a3' => [ 'a', '2 q' ],
				'c@' => '',
				'a2' => 'r b',
				'c2' => '',
			],
		);

		$this->assertSame('9djdj82h48djs9d2', $signed->oauthParameters['oauth_consumer_key']);
		$this->assertSame('kkk9d7dh3k39sjv7', $signed->oauthParameters['oauth_token']);
		$this->assertSame('HMAC-SHA1', $signed->oauthParameters['oauth_signature_method']);
		$this->assertSame('137131201', $signed->oauthParameters['oauth_timestamp']);
		$this->assertSame('7d8f3e4a', $signed->oauthParameters['oauth_nonce']);
		$this->assertSame('1.0', $signed->oauthParameters['oauth_version']);
		$this->assertSame('OB33pYjWAnf+xtOHN4Gmbdil168=', $signed->oauthParameters['oauth_signature']);
	}

	public function testSignOmitsOauthTokenWhenCredentialsHaveNone(): void {
		$signed = $this->signer()->sign('POST', 'http://example.com/request', new Credentials('key', 'secret'));

		$this->assertArrayNotHasKey('oauth_token', $signed->oauthParameters);
	}

	public function testSignIncludesOauthCallbackOnlyWhenGiven(): void {
		$withCallback = $this->signer()->sign(
			'POST',
			'http://example.com/request',
			new Credentials('key', 'secret'),
			callback: 'http://client.example.net/cb',
		);
		$withoutCallback = $this->signer()->sign('POST', 'http://example.com/request', new Credentials('key', 'secret'));

		$this->assertSame('http://client.example.net/cb', $withCallback->oauthParameters['oauth_callback']);
		$this->assertArrayNotHasKey('oauth_callback', $withoutCallback->oauthParameters);
	}

	public function testSignWithPlaintextOmitsTimestampAndNonce(): void {
		$signer = new RequestSigner(new PlaintextSigner);

		$signed = $signer->sign('POST', 'http://example.com/request', new Credentials('key', 'secret', 'token', 'tokensecret'));

		$this->assertArrayNotHasKey('oauth_timestamp', $signed->oauthParameters);
		$this->assertArrayNotHasKey('oauth_nonce', $signed->oauthParameters);
		$this->assertSame('secret&tokensecret', $signed->oauthParameters['oauth_signature']);
	}

}
