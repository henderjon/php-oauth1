<?php

namespace Oauth1;

use Oauth1\Exceptions\RequestVerificationException;
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

	private function verifier( ?FixedClock $clock = null, int $toleranceSeconds = 300 ): RequestVerifier {
		return new RequestVerifier(
			new HmacSha1Signer,
			new NonceStore(new InMemoryCache),
			$clock ?? new FixedClock(new \DateTimeImmutable('@137131201')),
			$toleranceSeconds,
		);
	}

	public function testVerifyAcceptsAFreshlySignedRequest(): void {
		$clock = new FixedClock(new \DateTimeImmutable('@137131201'));

		$this->verifier($clock)->verify('POST', self::URL, $this->credentials(), $this->sign($clock));

		$this->addToAssertionCount(1);
	}

	public function testVerifyRejectsATamperedParameter(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock, [ 'resource_link_id' => 'original' ]);

		$parameters['resource_link_id'] = 'tampered';

		try {
			$this->verifier($clock)->verify('POST', self::URL, $this->credentials(), $parameters);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			$this->assertSame(VerificationFailureReason::InvalidSignature, $exception->getReason());
		}
	}

	public function testVerifyRejectsAReplayedNonce(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$verifier   = $this->verifier($clock);
		$parameters = $this->sign($clock);

		$verifier->verify('POST', self::URL, $this->credentials(), $parameters);

		try {
			$verifier->verify('POST', self::URL, $this->credentials(), $parameters);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			$this->assertSame(VerificationFailureReason::NonceReplayed, $exception->getReason());
		}
	}

	public function testVerifyRejectsATimestampOutsideTheTolerance(): void {
		$signedAt = new FixedClock(new \DateTimeImmutable('@137131201'));
		$checkedAt = new FixedClock(new \DateTimeImmutable('@137131601')); // 400s later
		$parameters = $this->sign($signedAt);

		try {
			$this->verifier($checkedAt, 300)->verify('POST', self::URL, $this->credentials(), $parameters);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			$this->assertSame(VerificationFailureReason::TimestampOutOfWindow, $exception->getReason());
		}
	}

	public function testVerifyRejectsAnUnsupportedVersion(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock);

		$parameters['oauth_version'] = '2.0';

		try {
			$this->verifier($clock)->verify('POST', self::URL, $this->credentials(), $parameters);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			$this->assertSame(VerificationFailureReason::UnsupportedVersion, $exception->getReason());
		}
	}

	public function testVerifyRejectsAConsumerKeyMismatch(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock);

		try {
			$this->verifier($clock)->verify('POST', self::URL, $this->credentials()->withConsumerKey('different-key'), $parameters);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			$this->assertSame(VerificationFailureReason::ConsumerKeyMismatch, $exception->getReason());
		}
	}

	public function testVerifyRejectsAnUnsupportedSignatureMethod(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock);

		$parameters['oauth_signature_method'] = 'PLAINTEXT';

		try {
			$this->verifier($clock)->verify('POST', self::URL, $this->credentials(), $parameters);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			$this->assertSame(VerificationFailureReason::UnsupportedSignatureMethod, $exception->getReason());
		}
	}

	public function testVerifyRejectsAMissingRequiredParameter(): void {
		$clock      = new FixedClock(new \DateTimeImmutable('@137131201'));
		$parameters = $this->sign($clock);

		unset($parameters['oauth_nonce']);

		try {
			$this->verifier($clock)->verify('POST', self::URL, $this->credentials(), $parameters);
			$this->fail('Expected a RequestVerificationException');
		} catch ( RequestVerificationException $exception ) {
			$this->assertSame(VerificationFailureReason::MissingParameter, $exception->getReason());
		}
	}

	public function testVerifyAcceptsAPlaintextRequestWithNoTimestampOrNonce(): void {
		$signer     = new RequestSigner(new PlaintextSigner);
		$verifier   = new RequestVerifier(new PlaintextSigner, new NonceStore(new InMemoryCache));
		$parameters = $signer->sign('POST', self::URL, $this->credentials())->oauthParameters;

		$verifier->verify('POST', self::URL, $this->credentials(), $parameters);

		$this->addToAssertionCount(1);
	}

}
