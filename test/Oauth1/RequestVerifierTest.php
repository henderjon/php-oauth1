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
		$this->assertCount(1, $debug);
		$this->assertSame('oauth1.request_verified', $debug[0]['message']);
		$this->assertSame('key', $debug[0]['context']['consumer_key']);
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
		} catch ( SigningException ) {
			$errors = $logger->recordsAt('error');
			$this->assertCount(1, $errors);
			$this->assertSame('oauth1.signing_failed', $errors[0]['message']);
			$this->assertFalse($errors[0]['context']['security_relevant']);
		}
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
