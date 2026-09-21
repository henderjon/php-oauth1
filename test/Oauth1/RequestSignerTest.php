<?php

namespace Oauth1;

use Oauth1\Exceptions\SigningException;
use Oauth1\Fakes\ArrayLogger;
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

	public function testSignWithPlaintextLogsAnAlertEveryTime(): void {
		$logger = new ArrayLogger;
		$signer = new RequestSigner(new PlaintextSigner, logger: $logger);

		$signer->sign('POST', 'http://example.com/request', new Credentials('key', 'secret'));
		$signer->sign('POST', 'http://example.com/request', new Credentials('key', 'secret'));

		$alerts = $logger->recordsAt('alert');
		$this->assertCount(2, $alerts);
		$this->assertSame('oauth1.plaintext_method_used', $alerts[0]['message']);
	}

	public function testSignLogsADebugTraceOnSuccess(): void {
		$logger = new ArrayLogger;
		$signer = new RequestSigner(new HmacSha1Signer, new FixedNonceGenerator('nonce'), new FixedClock(new \DateTimeImmutable('@1')), $logger);

		$signer->sign('POST', 'http://example.com/request', new Credentials('key', 'secret'));

		$debug = $logger->recordsAt('debug');
		$this->assertCount(2, $debug);
		$this->assertSame('oauth1.signature_base_string_built', $debug[0]['message']);
		// No base_string_sha256 here - see RequestVerifierTest's matching assertion and
		// OAuth1Exception::getBaseStringSha256(). It fires on every call, success included, so
		// this event stays a bare trace like every other debug line.
		$this->assertArrayNotHasKey('base_string_sha256', $debug[0]['context']);
		$this->assertSame('oauth1.request_signed', $debug[1]['message']);
		$this->assertSame('key', $debug[1]['context']['consumer_key']);
		$this->assertSame([], $logger->recordsAboveDebug());
	}

	public function testSignNeverLogsAValueFromCallerSuppliedRequestParameters(): void {
		// $requestParameters is caller-supplied - for a Basic LTI launch, that includes PII
		// (lis_person_name_full, lis_person_contact_email_primary). This class has no way to
		// know which of an arbitrary caller's parameters are sensitive, so nothing it logs may
		// ever embed a value from them - only a hash of the base string they end up part of.
		$logger = new ArrayLogger;
		$signer = new RequestSigner(new HmacSha1Signer, logger: $logger);

		$signer->sign('POST', 'http://example.com/request', new Credentials('key', 'secret'), [
			'lis_person_name_full' => 'Ada Lovelace',
			'lis_person_contact_email_primary' => 'ada@example.test',
		]);

		$serializedLog = json_encode($logger->records);
		$this->assertStringNotContainsString('Ada Lovelace', $serializedLog);
		$this->assertStringNotContainsString('ada@example.test', $serializedLog);
	}

	public function testSignLogsADebugTraceWhenARequestParameterCollidesWithAReservedOauthKey(): void {
		$logger = new ArrayLogger;
		$signer = new RequestSigner(new HmacSha1Signer, logger: $logger);

		$signer->sign('POST', 'http://example.com/request', new Credentials('key', 'secret'), [
			'oauth_consumer_key' => 'a-fake-value',
			'foo' => 'bar',
		]);

		$debug = $logger->recordsAt('debug');
		$overridden = array_values(array_filter($debug, fn ( array $r ) => $r['message'] === 'oauth1.reserved_parameter_overridden'));
		$this->assertCount(1, $overridden);
		$this->assertSame([ 'oauth_consumer_key' ], $overridden[0]['context']['overridden_keys']);
	}

	public function testSignDoesNotLogAnOverrideWhenNoRequestParameterCollides(): void {
		$logger = new ArrayLogger;
		$signer = new RequestSigner(new HmacSha1Signer, logger: $logger);

		$signer->sign('POST', 'http://example.com/request', new Credentials('key', 'secret'), [ 'foo' => 'bar' ]);

		$overridden = array_filter($logger->recordsAt('debug'), fn ( array $r ) => $r['message'] === 'oauth1.reserved_parameter_overridden');
		$this->assertSame([], $overridden);
	}

	public function testSignLogsAnErrorAndRethrowsForAMalformedUrl(): void {
		$logger = new ArrayLogger;
		$signer = new RequestSigner(new HmacSha1Signer, logger: $logger);

		try {
			$signer->sign('POST', '/relative/path/no/host', new Credentials('key', 'secret'));
			$this->fail('Expected a SigningException');
		} catch ( SigningException $exception ) {
			$errors = $logger->recordsAt('error');
			$this->assertCount(1, $errors);
			$this->assertSame('oauth1.signing_failed', $errors[0]['message']);
			$this->assertSame('key', $errors[0]['context']['consumer_key']);
			$this->assertFalse($errors[0]['context']['security_relevant']);

			// SignatureBaseString itself has no Credentials to attach a consumer key to its
			// own exception - this rewraps it at the boundary where one is in scope, keeping
			// the original as getPrevious().
			$this->assertSame('key', $exception->getConsumerKey());
			$this->assertInstanceOf(SigningException::class, $exception->getPrevious());
			$this->assertNull($exception->getPrevious()->getConsumerKey());
			// SignatureBaseString::build() itself failed - there is no base string to hash.
			$this->assertNull($exception->getBaseStringSha256());

			// The exception thrown and the exception logged must be the same instance - not a
			// stale, unwrapped one whose own getConsumerKey() would contradict this same log
			// line's 'consumer_key' field.
			$this->assertSame($exception, $errors[0]['context']['exception']);
		}
	}

}
