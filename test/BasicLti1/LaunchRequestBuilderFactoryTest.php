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

		// Checks relative order of these two specific messages, not the exact full list - how
		// many intermediate debug checkpoints either layer logs is an implementation detail
		// this test does not care about; that one logger reaches both layers, in the right
		// order, is what it is asserting.
		$messages = array_column($logger->recordsAt('debug'), 'message');
		$this->assertSame(
			[ 'oauth1.request_signed', 'basiclti1.launch_built' ],
			array_values(array_intersect($messages, [ 'oauth1.request_signed', 'basiclti1.launch_built' ])),
		);
	}

}
