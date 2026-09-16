<?php

namespace BasicLti1;

use BasicLti1\Exceptions\InvalidLaunchException;
use Oauth1\Credentials;
use Oauth1\Exceptions\RequestVerificationException;
use Oauth1\Fakes\ArrayLogger;
use Oauth1\Fakes\FixedClock;
use Oauth1\Fakes\InMemoryCache;
use Oauth1\HmacSha1Signer;
use Oauth1\NonceStore;
use Oauth1\RequestVerifier;
use Oauth1\VerificationFailureReason;
use PHPUnit\Framework\TestCase;

class LaunchVerifierTest extends TestCase {

	private function verifier( ?FixedClock $clock = null, ?ArrayLogger $logger = null ): LaunchVerifier {
		return new LaunchVerifier(
			new RequestVerifier(
				new HmacSha1Signer,
				new NonceStore(new InMemoryCache),
				$clock ?? new FixedClock(new \DateTimeImmutable('@1251600739')),
			),
			$logger ?? new ArrayLogger,
		);
	}

	public function testVerifyAcceptsTheBasicLtiV1ImplementationGuidesOwnWorkedExample(): void {
		// Same example as LaunchRequestBuilderTest, fed in as a already-signed, already-received
		// launch this time - the guide's own printed oauth_signature, unmodified.
		$parameters = [
			'basiclti_submit' => 'Launch Endpoint with BasicLTI Data',
			'context_id' => '456434513',
			'context_label' => 'SI182',
			'context_title' => 'Design of Personal Environments',
			'lis_person_contact_email_primary' => 'user@school.edu',
			'lis_person_name_full' => 'Jane Q. Public',
			'lis_person_sourced_id' => 'school.edu:user',
			'lti_message_type' => 'basic-lti-launch-request',
			'lti_version' => 'LTI-1p0',
			'oauth_callback' => 'about:blank',
			'oauth_consumer_key' => '12345',
			'oauth_nonce' => 'c8350c0e47782d16d2fa48b2090c1d8f',
			'oauth_signature' => 'TPFPK4u3NwmtLt0nDMP1G1zG30U=',
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_timestamp' => '1251600739',
			'oauth_version' => '1.0',
			'resource_link_id' => '120988f929-274612',
			'roles' => 'Instructor',
			'tool_consumer_instance_description' => 'University of School (LMSng)',
			'tool_consumer_instance_guid' => 'lmsng.school.edu',
			'user_id' => '292832126',
		];

		$logger = new ArrayLogger;

		$this->verifier(logger: $logger)->verify(
			'http://dr-chuck.com/ims/php-simple/tool.php',
			new Credentials('12345', 'secret'),
			$parameters,
		);

		$debug = $logger->recordsAt('debug');
		$this->assertCount(1, $debug);
		$this->assertSame('basiclti1.launch_verified', $debug[0]['message']);
		$this->assertSame('12345', $debug[0]['context']['consumer_key']);
		$this->assertSame('120988f929-274612', $debug[0]['context']['resource_link_id']);
		$this->assertSame([], $logger->recordsAboveDebug());
	}

	public function testVerifyChecksTheSignatureBeforeAnyLtiContent(): void {
		// Wrong signature AND missing resource_link_id: the OAuth failure must win.
		$parameters = [
			'lti_message_type' => 'basic-lti-launch-request',
			'lti_version' => 'LTI-1p0',
			'oauth_consumer_key' => 'key',
			'oauth_nonce' => 'nonce',
			'oauth_signature' => 'not-a-real-signature',
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_timestamp' => '1251600739',
		];

		try {
			$this->verifier()->verify('http://example.com/launch', new Credentials('key', 'secret'), $parameters);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			$this->assertSame(VerificationFailureReason::InvalidSignature, $exception->getReason());
		}
	}

	/**
	 * A launch missing resource_link_id can never come from LaunchRequestBuilder, which
	 * refuses to build one (see LaunchRequestBuilderTest::testBuildThrowsWhenResourceLinkIdIsMissing).
	 * It can still arrive from some other Tool Consumer that signed correctly but omitted a
	 * required Basic LTI parameter - signing directly with RequestSigner here simulates exactly
	 * that, to prove LaunchVerifier still catches it once the signature itself checks out.
	 */
	public function testVerifyThrowsForAMissingResourceLinkIdOnceSignatureChecksOut(): void {
		$credentials = new Credentials('key', 'secret');
		$clock       = new FixedClock(new \DateTimeImmutable('@1251600739'));
		$logger      = new ArrayLogger;
		$signer      = new \Oauth1\RequestSigner(new HmacSha1Signer, clock: $clock);

		$parameters = [ 'lti_message_type' => Launch::MESSAGE_TYPE, 'lti_version' => Launch::VERSION ];
		$signed     = $signer->sign('POST', 'http://example.com/launch', $credentials, $parameters);
		$parameters = [ ...$parameters, ...$signed->oauthParameters ];

		try {
			$this->verifier($clock, $logger)->verify('http://example.com/launch', $credentials, $parameters);
			$this->fail('Expected an InvalidLaunchException');
		} catch ( InvalidLaunchException $exception ) {
			$this->assertSame(LaunchValidationFailureReason::MissingResourceLinkId, $exception->getReason());
			$this->assertLoggedError($logger, LaunchValidationFailureReason::MissingResourceLinkId);
			$this->assertSame('key', $exception->getConsumerKey());
		}
	}

	public function testVerifyRejectsARepeatedResourceLinkIdParameterAsMissing(): void {
		// A repeated resource_link_id (a list, not a scalar) is malformed input, not a valid
		// identifier - found while making sure this class never casts an array to string
		// before logging it.
		$credentials = new Credentials('key', 'secret');
		$clock       = new FixedClock(new \DateTimeImmutable('@1251600739'));
		$signer      = new \Oauth1\RequestSigner(new HmacSha1Signer, clock: $clock);

		$parameters = [
			'lti_message_type' => Launch::MESSAGE_TYPE,
			'lti_version' => Launch::VERSION,
			'resource_link_id' => [ 'a', 'b' ],
		];
		$signed     = $signer->sign('POST', 'http://example.com/launch', $credentials, $parameters);
		$parameters = [ ...$parameters, ...$signed->oauthParameters ];

		try {
			$this->verifier($clock)->verify('http://example.com/launch', $credentials, $parameters);
			$this->fail('Expected an InvalidLaunchException');
		} catch ( InvalidLaunchException $exception ) {
			$this->assertSame(LaunchValidationFailureReason::MissingResourceLinkId, $exception->getReason());
		}
	}

	public function testVerifyTruncatesAnOverlongResourceLinkIdBeforeLoggingIt(): void {
		$credentials = new Credentials('key', 'secret');
		$clock       = new FixedClock(new \DateTimeImmutable('@1251600739'));
		$logger      = new ArrayLogger;
		$signer      = new \Oauth1\RequestSigner(new HmacSha1Signer, clock: $clock);
		$overlong    = str_repeat('a', 500);

		$parameters = [ 'lti_message_type' => Launch::MESSAGE_TYPE, 'lti_version' => Launch::VERSION, 'resource_link_id' => $overlong ];
		$signed     = $signer->sign('POST', 'http://example.com/launch', $credentials, $parameters);
		$parameters = [ ...$parameters, ...$signed->oauthParameters ];

		$this->verifier($clock, $logger)->verify('http://example.com/launch', $credentials, $parameters);

		// The cut itself is 255 - see LaunchVerifier's own constant for why.
		$debug = $logger->recordsAt('debug');
		$this->assertSame(str_repeat('a', 255) . '...(truncated)', $debug[0]['context']['resource_link_id']);
	}

	public function testVerifyThrowsForAnInvalidMessageTypeOnceSignatureChecksOut(): void {
		$credentials = new Credentials('key', 'secret');
		$clock       = new FixedClock(new \DateTimeImmutable('@1251600739'));
		$logger      = new ArrayLogger;
		$signer      = new \Oauth1\RequestSigner(new HmacSha1Signer, clock: $clock);

		$parameters = [ 'lti_message_type' => 'something-else', 'lti_version' => Launch::VERSION, 'resource_link_id' => 'link-1' ];
		$signed     = $signer->sign('POST', 'http://example.com/launch', $credentials, $parameters);
		$parameters = [ ...$parameters, ...$signed->oauthParameters ];

		try {
			$this->verifier($clock, $logger)->verify('http://example.com/launch', $credentials, $parameters);
			$this->fail('Expected an InvalidLaunchException');
		} catch ( InvalidLaunchException $exception ) {
			$this->assertSame(LaunchValidationFailureReason::MissingOrInvalidMessageType, $exception->getReason());
			$this->assertLoggedError($logger, LaunchValidationFailureReason::MissingOrInvalidMessageType);
		}
	}

	private function assertLoggedError( ArrayLogger $logger, LaunchValidationFailureReason $reason ): void {
		$errors = $logger->recordsAt('error');
		$this->assertCount(1, $errors);
		$this->assertSame('basiclti1.launch_verification_failed', $errors[0]['message']);
		$this->assertSame($reason->name, $errors[0]['context']['reason']);
		$this->assertFalse($errors[0]['context']['security_relevant']);
	}

}
