<?php

namespace BasicLti1;

use BasicLti1\Exceptions\InvalidLaunchException;
use Oauth1\Credentials;
use Oauth1\Fakes\ArrayLogger;
use Oauth1\Fakes\FixedClock;
use Oauth1\Fakes\FixedNonceGenerator;
use Oauth1\HmacSha1Signer;
use Oauth1\RequestSigner;
use PHPUnit\Framework\TestCase;

class LaunchRequestBuilderTest extends TestCase {

	public function testBuildReproducesTheBasicLtiV1ImplementationGuidesOwnWorkedExample(): void {
		// Appendix B.5 of the Basic LTI v1.0 Implementation Guide: a full launch, with the exact
		// nonce/timestamp it used and the oauth_signature it printed for the result. Notably,
		// its base string omits oauth_callback even though the guide's own sample form submits
		// it - see LaunchRequestBuilder's docblock for why this class does the same.
		$signer = new RequestSigner(
			new HmacSha1Signer,
			new FixedNonceGenerator('c8350c0e47782d16d2fa48b2090c1d8f'),
			new FixedClock(new \DateTimeImmutable('@1251600739')),
		);
		$builder = new LaunchRequestBuilder($signer);

		$launch = $builder->build(
			'http://dr-chuck.com/ims/php-simple/tool.php',
			new Credentials('12345', 'secret'),
			[
				'basiclti_submit' => 'Launch Endpoint with BasicLTI Data',
				'context_id' => '456434513',
				'context_label' => 'SI182',
				'context_title' => 'Design of Personal Environments',
				'lis_person_contact_email_primary' => 'user@school.edu',
				'lis_person_name_full' => 'Jane Q. Public',
				'lis_person_sourced_id' => 'school.edu:user',
				'resource_link_id' => '120988f929-274612',
				'roles' => 'Instructor',
				'tool_consumer_instance_description' => 'University of School (LMSng)',
				'tool_consumer_instance_guid' => 'lmsng.school.edu',
				'user_id' => '292832126',
			],
		);

		$this->assertSame('TPFPK4u3NwmtLt0nDMP1G1zG30U=', $launch->parameters['oauth_signature']);
		$this->assertSame('about:blank', $launch->parameters['oauth_callback']);
		$this->assertSame('basic-lti-launch-request', $launch->parameters['lti_message_type']);
		$this->assertSame('LTI-1p0', $launch->parameters['lti_version']);
		$this->assertSame('HMAC-SHA1', $launch->parameters['oauth_signature_method']);
		$this->assertSame('1.0', $launch->parameters['oauth_version']);
		$this->assertSame('1251600739', $launch->parameters['oauth_timestamp']);
		$this->assertSame('c8350c0e47782d16d2fa48b2090c1d8f', $launch->parameters['oauth_nonce']);
		$this->assertSame('12345', $launch->parameters['oauth_consumer_key']);
	}

	public function testBuildThrowsWhenResourceLinkIdIsMissing(): void {
		$builder = new LaunchRequestBuilder(new RequestSigner(new HmacSha1Signer));

		try {
			$builder->build('http://example.com/launch', new Credentials('key', 'secret'), []);
			$this->fail('Expected an InvalidLaunchException');
		} catch ( InvalidLaunchException $exception ) {
			$this->assertSame(LaunchValidationFailureReason::MissingResourceLinkId, $exception->getReason());
		}
	}

	public function testBuildOverridesACallerSuppliedMessageTypeOrVersion(): void {
		$builder = new LaunchRequestBuilder(new RequestSigner(new HmacSha1Signer));

		$launch = $builder->build('http://example.com/launch', new Credentials('key', 'secret'), [
			'resource_link_id' => 'link-1',
			'lti_message_type' => 'something-else',
			'lti_version' => 'LTI-9p9',
		]);

		$this->assertSame('basic-lti-launch-request', $launch->parameters['lti_message_type']);
		$this->assertSame('LTI-1p0', $launch->parameters['lti_version']);
	}

	public function testBuildLogsADebugTraceOnSuccess(): void {
		$logger  = new ArrayLogger;
		$builder = new LaunchRequestBuilder(new RequestSigner(new HmacSha1Signer), $logger);

		$builder->build('http://example.com/launch', new Credentials('key', 'secret'), [ 'resource_link_id' => 'link-1' ]);

		$debug = $logger->recordsAt('debug');
		$this->assertCount(1, $debug);
		$this->assertSame('basiclti1.launch_built', $debug[0]['message']);
		$this->assertSame('key', $debug[0]['context']['consumer_key']);
		$this->assertSame('link-1', $debug[0]['context']['resource_link_id']);
		$this->assertSame([], $logger->recordsAboveDebug());
	}

	public function testBuildLogsADebugTraceWhenACallerSuppliedMessageTypeOrVersionIsOverridden(): void {
		$logger  = new ArrayLogger;
		$builder = new LaunchRequestBuilder(new RequestSigner(new HmacSha1Signer), $logger);

		$builder->build('http://example.com/launch', new Credentials('key', 'secret'), [
			'resource_link_id' => 'link-1',
			'lti_message_type' => 'something-else',
			'lti_version' => 'LTI-9p9',
		]);

		$debug = $logger->recordsAt('debug');
		$overridden = array_values(array_filter($debug, fn ( array $r ) => $r['message'] === 'basiclti1.reserved_parameter_overridden'));
		$this->assertCount(1, $overridden);
		$this->assertSame([ 'lti_message_type', 'lti_version' ], $overridden[0]['context']['overridden_keys']);
	}

	public function testBuildDoesNotLogAnOverrideWhenTheCallerNeverSuppliedMessageTypeOrVersion(): void {
		$logger  = new ArrayLogger;
		$builder = new LaunchRequestBuilder(new RequestSigner(new HmacSha1Signer), $logger);

		$builder->build('http://example.com/launch', new Credentials('key', 'secret'), [ 'resource_link_id' => 'link-1' ]);

		$overridden = array_filter($logger->recordsAt('debug'), fn ( array $r ) => $r['message'] === 'basiclti1.reserved_parameter_overridden');
		$this->assertSame([], $overridden);
	}

	public function testBuildLogsAnErrorAndThrowsWhenResourceLinkIdIsMissing(): void {
		$logger  = new ArrayLogger;
		$builder = new LaunchRequestBuilder(new RequestSigner(new HmacSha1Signer), $logger);

		try {
			$builder->build('http://example.com/launch', new Credentials('key', 'secret'), []);
			$this->fail('Expected an InvalidLaunchException');
		} catch ( InvalidLaunchException $exception ) {
			$errors = $logger->recordsAt('error');
			$this->assertCount(1, $errors);
			$this->assertSame('basiclti1.launch_build_failed', $errors[0]['message']);
			$this->assertSame(LaunchValidationFailureReason::MissingResourceLinkId->name, $errors[0]['context']['reason']);
			$this->assertFalse($errors[0]['context']['security_relevant']);
			$this->assertSame('key', $exception->getConsumerKey());
		}
	}

}
