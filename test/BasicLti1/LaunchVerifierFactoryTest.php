<?php

namespace BasicLti1;

use Oauth1\Credentials;
use Oauth1\Fakes\ArrayLogger;
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

	public function testMakeThreadsOneLoggerThroughBothTheBasicLti1AndOauth1Layers(): void {
		$credentials = new Credentials('key', 'secret');
		$launch      = (new LaunchRequestBuilderFactory)->make()->build(
			'http://example.com/launch',
			$credentials,
			[ 'resource_link_id' => 'link-1' ],
		);

		$logger = new ArrayLogger;
		(new LaunchVerifierFactory(logger: $logger))->make(new InMemoryCache)
			->verify('http://example.com/launch', $credentials, $launch->parameters);

		// See LaunchRequestBuilderFactoryTest's matching test for why this checks relative
		// order of these two messages rather than the exact full list.
		$messages = array_column($logger->recordsAt('debug'), 'message');
		$this->assertSame(
			[ 'oauth1.request_verified', 'basiclti1.launch_verified' ],
			array_values(array_intersect($messages, [ 'oauth1.request_verified', 'basiclti1.launch_verified' ])),
		);
	}

}
