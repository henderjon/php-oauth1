<?php

namespace BasicLti1;

use Oauth1\Credentials;
use Oauth1\Fakes\ArrayLogger;
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

	public function testMakeThreadsOneLoggerThroughBothTheBasicLti1AndOauth1Layers(): void {
		$logger = new ArrayLogger;

		(new LaunchRequestBuilderFactory(logger: $logger))->make()->build(
			'http://example.com/launch',
			new Credentials('key', 'secret'),
			[ 'resource_link_id' => 'link-1' ],
		);

		$messages = array_column($logger->recordsAt('debug'), 'message');
		$this->assertSame([ 'oauth1.request_signed', 'basiclti1.launch_built' ], $messages);
	}

}
