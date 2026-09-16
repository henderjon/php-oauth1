<?php

namespace Oauth1;

use Oauth1\Exceptions\RequestVerificationException;
use Oauth1\Exceptions\SigningException;
use Oauth1\Fakes\ArrayLogger;
use Oauth1\Fakes\FixedClock;
use Oauth1\Fakes\FixedNonceGenerator;
use Oauth1\Fakes\InMemoryCache;
use PHPUnit\Framework\TestCase;

class RequestVerifierTest extends TestCase {

	private const URL = 'http://example.com/request';

	private function credentials(): Credentials {
		return new Credentials('key', 'secret', 'token', 'tokensecret');
	}

	private function sign( ?FixedClock $clock = null, array $requestParameters = [] ): array {
		$clock  = $clock ?? new FixedClock(new \DateTimeImmutable('@137131201'));
		$signer = new RequestSigner(new HmacSha1Signer, new FixedNonceGenerator('7d8f3e4a'), $clock);
		$signed = $signer->sign('POST', self::URL, $this->credentials(), $requestParameters);

		return [ ...$requestParameters, ...$signed->oauthParameters ];
	}

	private function verifier( ?FixedClock $clock = null, int $toleranceSeconds = 300, ?ArrayLogger $logger = null ): RequestVerifier {
		return new RequestVerifier(
			new HmacSha1Signer,
			new NonceStore(new InMemoryCache),
			$clock ?? new FixedClock(new \DateTimeImmutable('@137131201')),
			$toleranceSeconds,
			$logger ?? new ArrayLogger,
		);
	}

	/**
	 * @return array{0: RequestVerificationException, 1: ArrayLogger}
	 */
	private function assertRejected( callable $verify ): array {
		$logger = new ArrayLogger;

		try {
			$verify($logger);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			return [ $exception, $logger ];
		}
	}

	public function testVerifyAcceptsAFreshlySignedRequestAndLogsADebugTrace(): void {
		$clock  = new FixedClock(new \DateTimeImmutable('@137131201'));
		$logger = new ArrayLogger;

		$this->verifier($clock, logger: $logger)->verify('POST', self::URL, $this->credentials(), $this->sign($clock));

		$debug = $logger->recordsAt('debug');
		$this->assertCount(2, $debug);
		$this->assertSame('oauth1.signature_base_string_built', $debug[0]['message']);
		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $debug[0]['context']['base_string_sha256']);
		$this->assertSame('oauth1.request_verified', $debug[1]['message']);
		$this->assertSame('key', $debug[1]['context']['consumer_key']);
		$this->assertSame([], $logger->recordsAboveDebug());
	}

	public function testVerifyRejectsATamperedParameter(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock, [ 'resource_link_id' => 'original' ]);
		$parameters['resource_link_id'] = 'tampered';

		[ $exception, $logger ] = $this->assertRejected(
			fn ( $logger ) => $this->verifier($clock, logger: $logger)->verify('POST', self::URL, $this->credentials(), $parameters),
		);

		$this->assertSame(VerificationFailureReason::InvalidSignature, $exception->getReason());
		$this->assertLoggedError($logger, VerificationFailureReason::InvalidSignature, true);
		$this->assertSame('key', $exception->getConsumerKey());
	}

	public function testVerifyRejectsAReplayedNonce(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$logger     = new ArrayLogger;
		$verifier   = $this->verifier($clock, logger: $logger);
		$parameters = $this->sign($clock);

		$verifier->verify('POST', self::URL, $this->credentials(), $parameters);

		try {
			$verifier->verify('POST', self::URL, $this->credentials(), $parameters);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			$this->assertSame(VerificationFailureReason::NonceReplayed, $exception->getReason());
			$this->assertLoggedError($logger, VerificationFailureReason::NonceReplayed, true);
		}
	}

	/**
	 * A forged/corrupted request reusing a legitimate nonce, timestamp, and consumer key -
	 * oauth_nonce/oauth_timestamp/oauth_consumer_key are all plaintext, visible to anyone who can
	 * see the wire - must not burn that nonce. Otherwise an attacker with no ability to sign
	 * anything could still deny the legitimate request that nonce belongs to, by sending a
	 * forgery first: exactly the denial-of-service vector this class's own docblock now
	 * documents.
	 */
	public function testVerifyDoesNotClaimTheNonceWhenTheSignatureIsInvalid(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$logger     = new ArrayLogger;
		$verifier   = $this->verifier($clock, logger: $logger);
		$parameters = $this->sign($clock);

		$forged = $parameters;
		$forged['oauth_signature'] = 'not-the-real-signature';

		try {
			$verifier->verify('POST', self::URL, $this->credentials(), $forged);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			$this->assertSame(VerificationFailureReason::InvalidSignature, $exception->getReason());
		}

		// The genuinely signed request, reusing the same nonce/timestamp the forgery above
		// copied, must still succeed - the forgery never actually claimed the nonce.
		$verifier->verify('POST', self::URL, $this->credentials(), $parameters);

		$this->assertSame('oauth1.request_verified', $logger->recordsAt('debug')[array_key_last($logger->recordsAt('debug'))]['message']);
	}

	public function testVerifyRejectsATimestampOutsideTheTolerance(): void {
		$signedAt  = new FixedClock(new \DateTimeImmutable('@137131201'));
		$checkedAt = new FixedClock(new \DateTimeImmutable('@137131601')); // 400s later
		$parameters = $this->sign($signedAt);

		[ $exception, $logger ] = $this->assertRejected(
			fn ( $logger ) => $this->verifier($checkedAt, 300, $logger)->verify('POST', self::URL, $this->credentials(), $parameters),
		);

		$this->assertSame(VerificationFailureReason::TimestampOutOfWindow, $exception->getReason());
		$this->assertLoggedError($logger, VerificationFailureReason::TimestampOutOfWindow, false);
	}

	public function testVerifyRejectsAnUnsupportedVersion(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock);
		$parameters['oauth_version'] = '2.0';

		[ $exception, $logger ] = $this->assertRejected(
			fn ( $logger ) => $this->verifier($clock, logger: $logger)->verify('POST', self::URL, $this->credentials(), $parameters),
		);

		$this->assertSame(VerificationFailureReason::UnsupportedVersion, $exception->getReason());
		$this->assertLoggedError($logger, VerificationFailureReason::UnsupportedVersion, false);
	}

	public function testVerifyRejectsAConsumerKeyMismatch(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock);

		[ $exception, $logger ] = $this->assertRejected(
			fn ( $logger ) => $this->verifier($clock, logger: $logger)
				->verify('POST', self::URL, $this->credentials()->withConsumerKey('different-key'), $parameters),
		);

		$this->assertSame(VerificationFailureReason::ConsumerKeyMismatch, $exception->getReason());
		$this->assertLoggedError($logger, VerificationFailureReason::ConsumerKeyMismatch, false);
	}

	public function testVerifyCapsAnOverlongIncomingConsumerKeyInTheLogButNotInTheException(): void {
		// The incoming oauth_consumer_key is attacker-controlled and unvalidated until it has
		// been checked against $credentials->consumerKey. Only the log line is capped, never
		// the value a comparison runs against (a real mismatch is still correctly detected
		// below) and never what the exception itself hands back to calling code - a caller
		// may need the real value to look something up in its own store; see this class's own
		// docblock for why that is a deliberate divergence from Oidc\AuthorizationStateStore's
		// own choice to cap its exception's state too.
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$overlong   = str_repeat('a', 500);
		$parameters = [
			'oauth_consumer_key' => $overlong,
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_signature' => 'irrelevant',
			'oauth_timestamp' => '137131201',
			'oauth_nonce' => 'nonce',
		];

		[ $exception, $logger ] = $this->assertRejected(
			fn ( $logger ) => $this->verifier($clock, logger: $logger)->verify('POST', self::URL, $this->credentials(), $parameters),
		);

		$this->assertSame(VerificationFailureReason::ConsumerKeyMismatch, $exception->getReason());
		$this->assertSame($overlong, $exception->getConsumerKey());

		$errors = $logger->recordsAt('error');
		// The cut itself is 255, not the 64 Oidc\AuthorizationStateStore uses for its own
		// state - see this class's own docblock for why the two warrant different caps.
		$this->assertSame(str_repeat('a', 255) . '...(truncated)', $errors[0]['context']['consumer_key']);
	}

	public function testVerifyRejectsAnUnsupportedSignatureMethod(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock);
		$parameters['oauth_signature_method'] = 'PLAINTEXT';

		[ $exception, $logger ] = $this->assertRejected(
			fn ( $logger ) => $this->verifier($clock, logger: $logger)->verify('POST', self::URL, $this->credentials(), $parameters),
		);

		$this->assertSame(VerificationFailureReason::UnsupportedSignatureMethod, $exception->getReason());
		$this->assertLoggedError($logger, VerificationFailureReason::UnsupportedSignatureMethod, false);
	}

	public function testVerifyRejectsAMissingRequiredParameter(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock);
		unset($parameters['oauth_nonce']);

		[ $exception, $logger ] = $this->assertRejected(
			fn ( $logger ) => $this->verifier($clock, logger: $logger)->verify('POST', self::URL, $this->credentials(), $parameters),
		);

		$this->assertSame(VerificationFailureReason::MissingParameter, $exception->getReason());
		$this->assertLoggedError($logger, VerificationFailureReason::MissingParameter, false);
	}

	public function testVerifyLogsAnErrorAndRethrowsForAMalformedUrl(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock);
		$logger     = new ArrayLogger;

		try {
			$this->verifier($clock, logger: $logger)->verify('POST', '/relative/path/no/host', $this->credentials(), $parameters);
			$this->fail('Expected a SigningException');
		} catch ( SigningException $exception ) {
			$errors = $logger->recordsAt('error');
			$this->assertCount(1, $errors);
			$this->assertSame('oauth1.verifying_failed', $errors[0]['message']);
			$this->assertFalse($errors[0]['context']['security_relevant']);

			// See RequestSignerTest's matching test for why this is rewrapped, not rethrown
			// as-is, and why the logged exception and the thrown one must be identical.
			$this->assertSame('key', $exception->getConsumerKey());
			$this->assertInstanceOf(SigningException::class, $exception->getPrevious());
			$this->assertNull($exception->getPrevious()->getConsumerKey());
			$this->assertSame($exception, $errors[0]['context']['exception']);
		}
	}

	public function testVerifyNeverLogsAValueFromRequestParameters(): void {
		// See RequestSignerTest's matching test - the same PII-in-launch-parameters concern
		// applies to the receiving side.
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$logger     = new ArrayLogger;
		$parameters = $this->sign($clock, [
			'lis_person_name_full' => 'Ada Lovelace',
			'lis_person_contact_email_primary' => 'ada@example.test',
		]);

		$this->verifier($clock, logger: $logger)->verify('POST', self::URL, $this->credentials(), $parameters);

		$serializedLog = json_encode($logger->records);
		$this->assertStringNotContainsString('Ada Lovelace', $serializedLog);
		$this->assertStringNotContainsString('ada@example.test', $serializedLog);
	}

	public function testVerifyAcceptsAPlaintextRequestWithNoTimestampOrNonce(): void {
		$signer     = new RequestSigner(new PlaintextSigner);
		$verifier   = new RequestVerifier(new PlaintextSigner, new NonceStore(new InMemoryCache));
		$parameters = $signer->sign('POST', self::URL, $this->credentials())->oauthParameters;

		$verifier->verify('POST', self::URL, $this->credentials(), $parameters);

		$this->addToAssertionCount(1);
	}

	public function testVerifyWithPlaintextLogsAnAlert(): void {
		$logger     = new ArrayLogger;
		$signer     = new RequestSigner(new PlaintextSigner);
		$verifier   = new RequestVerifier(new PlaintextSigner, new NonceStore(new InMemoryCache), logger: $logger);
		$parameters = $signer->sign('POST', self::URL, $this->credentials())->oauthParameters;

		$verifier->verify('POST', self::URL, $this->credentials(), $parameters);

		$alerts = $logger->recordsAt('alert');
		$this->assertCount(1, $alerts);
		$this->assertSame('oauth1.plaintext_method_used', $alerts[0]['message']);
	}

	private function assertLoggedError( ArrayLogger $logger, VerificationFailureReason $reason, bool $securityRelevant ): void {
		$errors = $logger->recordsAt('error');
		$this->assertCount(1, $errors);
		$this->assertSame('oauth1.verification_failed', $errors[0]['message']);
		$this->assertSame($reason->name, $errors[0]['context']['reason']);
		$this->assertSame($securityRelevant, $errors[0]['context']['security_relevant']);
	}

}
