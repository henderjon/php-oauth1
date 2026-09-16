<?php

namespace BasicLti1;

use Oauth1\Credentials;
use Oauth1\Fakes\InMemoryCache;
use PHPUnit\Framework\TestCase;

class LaunchVerifierFactoryTest extends TestCase {

	public function testMakeBuildsALaunchVerifierThatAcceptsAMatchingHmacSha1Launch(): void {
		$credentials = new Credentials('key', 'secret');
		$launch      = (new LaunchRequestBuilderFactory)->make()->build(
			'http://example.com/launch',
			$credentials,
			[ 'resource_link_id' => 'link-1' ],
		);

		(new LaunchVerifierFactory)->make(new InMemoryCache)->verify('http://example.com/launch', $credentials, $launch->parameters);

		$this->addToAssertionCount(1);
	}

}
