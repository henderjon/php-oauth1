<?php

namespace BasicLti1;

use Oauth1\Credentials;
use PHPUnit\Framework\TestCase;

class LaunchRequestBuilderFactoryTest extends TestCase {

	public function testMakeBuildsALaunchRequestBuilderThatSignsWithHmacSha1(): void {
		$launch = (new LaunchRequestBuilderFactory)->make()->build(
			'http://example.com/launch',
			new Credentials('key', 'secret'),
			[ 'resource_link_id' => 'link-1' ],
		);

		$this->assertSame('HMAC-SHA1', $launch->parameters['oauth_signature_method']);
	}

}
