<?php

namespace Oauth1;

use PHPUnit\Framework\TestCase;

class SignedRequestTest extends TestCase {

	public function testAuthorizationHeaderValueQuotesAndEncodesEachParameter(): void {
		$signed = new SignedRequest([
			'oauth_consumer_key' => '0685bd9184jfhq22',
			'oauth_signature' => 'wOJIO9A2W5mFwDgiDvZbTSMK/PY=',
		]);

		$this->assertSame(
			'OAuth oauth_consumer_key="0685bd9184jfhq22", oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D"',
			$signed->authorizationHeaderValue(),
		);
	}

	public function testAuthorizationHeaderValueIncludesAnEncodedRealmFirstWhenGiven(): void {
		$signed = new SignedRequest([ 'oauth_consumer_key' => 'key' ]);

		$this->assertSame(
			'OAuth realm="Example", oauth_consumer_key="key"',
			$signed->authorizationHeaderValue('Example'),
		);
	}

}
